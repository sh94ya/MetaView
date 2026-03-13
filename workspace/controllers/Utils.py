import ipaddress
from pyparsing import (
    Word, alphas, alphanums, quotedString, removeQuotes, oneOf, infixNotation,
    opAssoc, nums, Combine, Literal, ParserElement, Optional
)
from sqlalchemy import and_, or_, not_, text, cast
from sqlalchemy.sql import operators
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import aliased

ParserElement.enablePackrat()
from workspace.models.migration import Hosts, Events, Tags, HostsTags, Services, Notes, Loots, MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs


# Словарь алиасов, который вы используете при построении запроса.
# Обратите внимание: для связей по creds нам понадобятся alias-объекты при join'ах в основном запросе.
aliases = {
    "hosts": Hosts,
    "services": Services,
    "creds_cores": MetasploitCredentialCores,
    "creds_priv": MetasploitCredentialPrivates,
    "creds_pub": MetasploitCredentialPublics,
    "creds_realm": MetasploitCredentialRealms,
    # можно добавлять другие алиасы
}

# --- helper для CIDR ---
def is_cidr_literal(s):
    if not isinstance(s, str):
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        return False

# --- Парсер (упрощённый, как в предыдущем примере) ---
integer = Combine(Optional(Literal('-')) + Word(nums)).setParseAction(lambda t: int(t[0]))
string = quotedString.setParseAction(removeQuotes)
identifier = Combine(Word(alphas + "_", alphanums + "_.") )  # table.field
comp_op = oneOf("== != > >= < <= =~ !~ in notin contains << >> && ||")

class Field:
    def __init__(self, toks): self.name = toks[0]
    def eval(self, aliases_for_resolve):
        # Custom resolve: support creds.* mapping
        if "." not in self.name:
            raise ValueError("Field must be table.column")
        table, col = self.name.split(".", 1)
        table = table.lower()
        col = col.lower()

        # creds.* mapping
        if table == "creds":
            if col == "password":
                return aliases_for_resolve["creds_priv"].data
            if col == "username":
                return aliases_for_resolve["creds_pub"].username
            if col == "realm":
                return aliases_for_resolve["creds_realm"].value
            # если нужен доступ к другим полям cores:
            if col == "core_id" or col == "id":
                return aliases_for_resolve.get("creds_cores").id
            raise KeyError(f"Unknown creds field: {col}")

        # otherwise normal resolution (hosts, services, ...)
        if table not in aliases_for_resolve:
            raise KeyError(f"Unknown alias/table: {table}")
        model_or_alias = aliases_for_resolve[table]
        return getattr(model_or_alias, col)

class Value:
    def __init__(self, toks): self.v = toks[0]
    def eval(self, aliases): return self.v

class Comparison:
    op_map = {
        "==": operators.eq,
        "!=": operators.ne,
        ">": operators.gt,
        ">=": operators.ge,
        "<": operators.lt,
        "<=": operators.le,
    }
    def __init__(self, toks):
        self.left = toks[0]
        self.op = toks[1]
        self.right = toks[2]
    def eval(self, aliases_for_resolve):
        left_col = self.left.eval(aliases_for_resolve) if hasattr(self.left, "eval") else self.left
        right_val = self.right.eval(aliases_for_resolve) if hasattr(self.right, "eval") else self.right
        op = self.op

        # special inet handling for hosts.address
        try:
            col_name = getattr(left_col, "name", None)
            table_name = getattr(getattr(left_col, "table", None), "name", None)
        except Exception:
            col_name = table_name = None

        if table_name == "hosts" and col_name == "address":
            if op in ("==", "!="):
                if isinstance(right_val, str) and is_cidr_literal(right_val):
                    cond = left_col.op("<<=")(cast(text(f"'{right_val}'"), INET))
                else:
                    cond = left_col == right_val
                return cond if op == "==" else ~cond
            if op in ("<<", ">>", "&&"):
                if isinstance(right_val, str):
                    return left_col.op(op)(cast(text(f"'{right_val}'"), INET))
                return left_col.op(op)(right_val)
            if op == "in":
                if isinstance(right_val, (list, tuple)):
                    clauses = [left_col.op("<<=")(cast(text(f"'{r}'"), INET)) for r in right_val]
                    return or_(*clauses)
                return left_col.op("<<=")(cast(text(f"'{right_val}'"), INET))

        # generic
        if op in self.op_map:
            return self.op_map[op](left_col, right_val)
        if op == "in":
            return left_col.in_(right_val if isinstance(right_val, (list, tuple)) else [right_val])
        if op == "notin":
            return ~left_col.in_(right_val if isinstance(right_val, (list, tuple)) else [right_val])
        if op == "=~":
            return left_col.op("~")(right_val)
        if op == "!~":
            return left_col.op("!~")(right_val)
        if op == "contains":
            return left_col.contains(right_val)
        raise ValueError("Unsupported operator: " + op)

# Грамматика и сборка булевых выражений
field_expr = identifier.copy().setParseAction(lambda t: Field(t))
value_expr = (string | integer).setParseAction(lambda t: Value(t))
atom = field_expr | value_expr
comp_expr = (atom + comp_op + atom).setParseAction(lambda t: Comparison([t[0], t[1], t[2]]))

expr = infixNotation(
    comp_expr | field_expr,
    [
        ("!", 1, opAssoc.RIGHT, lambda t: ["NOT", t[0][1]]),
        ("&&", 2, opAssoc.LEFT, lambda t: ["AND"] + t[0][0::2]),
        ("||", 2, opAssoc.LEFT, lambda t: ["OR"] + t[0][0::2]),
    ],
)

def build_condition(node, aliases):
    # leaf
    if hasattr(node, "eval"):
        return node.eval(aliases)

    # list case
    if isinstance(node, list):
        if not node:
            return None

        # Если первый элемент — оператор в форме ["AND", ...]
        if node[0] in ("AND", "OR", "NOT"):
            op = node[0]
            if op == "NOT":
                return ~build_condition(node[1], aliases)
            comb = and_ if op == "AND" else or_
            parts = [build_condition(el, aliases) for el in node[1:]]
            parts = [p for p in parts if p is not None]
            if not parts:
                return None
            return comb(*parts) if len(parts) > 1 else parts[0]

        # Иначе структура может быть чередой: [left, op, right, op2, right2, ...]
        # Пройдём слева направо и построим дерево с учётом приоритета (left-associative как у infixNotation).
        # Сначала соберём элементы в единообразный список (flatten вложенные списки-обёртки)
        elems = []
        for el in node:
            # если элемент — список-обёртка из одного элемента, извлечём его
            if isinstance(el, list) and len(el) == 1:
                elems.append(el[0])
            else:
                elems.append(el)

        # теперь elems like [left, 'AND', right, 'OR', right2, ...]
        # будем аккуратно комбинировать слева направо: ((left op right) op2 right2) ...
        if not elems:
            return None
        # начнём с первого операнда
        cur = elems[0]
        cur_cond = build_condition(cur, aliases) if not hasattr(cur, "eval") else cur.eval(aliases)
        i = 1
        while i < len(elems):
            op = elems[i]
            rhs = elems[i + 1]
            rhs_cond = build_condition(rhs, aliases) if not hasattr(rhs, "eval") else rhs.eval(aliases)
            if op == "AND":
                cur_cond = and_(cur_cond, rhs_cond)
            elif op == "OR":
                cur_cond = or_(cur_cond, rhs_cond)
            else:
                raise ValueError("Unknown boolean operator in parsed tree: " + repr(op))
            i += 2
        return cur_cond

    raise ValueError("Unsupported parsed node: " + repr(node))

# Функция применения фильтра к запросу
def apply_dynamic_filter(q, filter_str, aliases_for_resolve):
    parsed = expr.parseString(filter_str, parseAll=True)[0]
    cond = build_condition(parsed, aliases_for_resolve)
    if cond is not None:
        return q.filter(cond)
    return q
# OP_MAP как раньше
OP_MAP = {
    'eq': lambda c, v: c == v,
    'ne': lambda c, v: c != v,
    'lt': lambda c, v: c < v,
    'lte': lambda c, v: c <= v,
    'gt': lambda c, v: c > v,
    'gte': lambda c, v: c >= v,
    'in': lambda c, v: c.in_(v),
    'like': lambda c, v: c.like(v),
    'ilike': lambda c, v: c.ilike(v),
}

# карта имен отношений (если у моделей заданы relationship(), можно использовать их напрямую)
RELATION_MODELS = {
    'hosts': Hosts,
    'tag': Tags,
    'services': Services,
    'notes': Notes,
    'loots': Loots,
    'creds': (MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices),
    'vulns': (Vulns, VulnDetails, VulnAttempts, VulnsRefs)
}

def resolve_path_and_column(root_model, path: List[str]):
    """
    path: ['tag','name','ilike'] or ['service','port','gte']
    возвращает (joins, column, op_name)
    joins: list of (model_or_alias, join_condition_source_attr, join_condition_target_attr)
    column: SQLAlchemy column object
    op_name: строка операции
    """
    # extract op if last part is an operator key
    op = 'eq'
    if path and path[-1] in OP_MAP:
        op = path[-1]
        path = path[:-1]
    if not path:
        raise ValueError("Invalid filter key")
    # final part is column name
    *rels, col_name = path

    current_model = root_model
    joins = []  # tuples (target_model_or_alias, onclause)
    alias_map = {}

    for rel in rels:
        # resolve relation name to a model or relationship attribute
        if rel in alias_map:
            current_alias = alias_map[rel]
            current_model = current_alias
            continue

        # try relationship attribute on current_model
        if hasattr(current_model, rel):
            rel_attr = getattr(current_model, rel)
            # if this is a relationship property, SQLAlchemy descriptor will allow access to .property.mapper.class_
            try:
                target_model = rel_attr.property.mapper.class_
            except Exception:
                # fallback: check RELATION_MODELS map
                target_model = RELATION_MODELS.get(rel)
                if target_model is None:
                    raise ValueError(f"Unknown relation {rel} on {current_model}")
        else:
            # fallback to RELATION_MODELS mapping
            target_model = RELATION_MODELS.get(rel)
            if target_model is None:
                raise ValueError(f"Unknown relation {rel} for model {current_model}")

        alias = aliased(target_model)
        alias_map[rel] = alias
        # create a generic join condition: try common naming conventions
        # e.g. Host.id == alias.host_id  or alias.id == Host.{rel}_id
        if hasattr(alias, 'host_id'):
            onclause = getattr(alias, 'host_id') == getattr(root_model, 'id')
        elif hasattr(alias, f"{current_model.__name__.lower()}_id"):
            onclause = getattr(alias, f"{current_model.__name__.lower()}_id") == getattr(current_model, 'id')
        else:
            # leave onclause None — caller must rely on ORM relationships or explicit joins
            onclause = None

        joins.append((alias, onclause))
        current_model = alias

    # get column from current_model
    if not hasattr(current_model, col_name):
        raise ValueError(f"Unknown column {col_name} on {current_model}")
    column = getattr(current_model, col_name)
    return joins, column, op

def build_filters_with_joins(root_model, filters: Dict[str, Any]):
    """
    Возвращает tuple (filter_expressions, joins) — список выражений и список join targets.
    joins: list of (alias, onclause)
    """
    exprs = []
    joins: List[Tuple[Any, Any]] = []
    for key, value in filters.items():
        parts = key.split('__')
        # if last part is operator token, keep it; otherwise default 'eq'
        if parts[-1] in OP_MAP:
            op_name = parts[-1]
            path = parts[:-1]
        else:
            op_name = 'eq'
            path = parts
        joins_for_key, column, _ = resolve_path_and_column(root_model, path + [op_name])  # resolve handles op detection
        # accumulate joins (avoid duplicates)
        for j in joins_for_key:
            if j not in joins:
                joins.append(j)
        # build expression
        fn = OP_MAP.get(op_name)
        if fn is None:
            raise ValueError(f"Unknown op {op_name}")
        if op_name == 'in' and not isinstance(value, (list, tuple)):
            raise ValueError("value for __in must be list/tuple")
        exprs.append(fn(column, value))
    return exprs, joins


