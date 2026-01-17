from workspace.models.migration import (
        Hosts, Events, Tags, HostsTags, Services, Notes, Loots, 
        MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics,
        MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, 
        MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs)
import traceback
import re
from pyparsing import (
    Word, alphas, alphanums, nums, oneOf, Group, Optional, 
    infixNotation, opAssoc, QuotedString, Combine, Literal, 
    Suppress, ParseException, ZeroOrMore, ParseResults, Regex,
    Forward, pyparsing_common, Keyword, CaselessKeyword, delimitedList
)
from sqlalchemy import and_, or_, not_, null, func
from sqlalchemy.dialects.postgresql import INET

model_mapping = {
    'hosts': Hosts,
    'tag': Tags,
    'services': Services,
    'notes': Notes,
    'loots': Loots,
    'metasploitcredentialcores': MetasploitCredentialCores,
    'metasploitcredentialpublics': MetasploitCredentialPublics,
    'metasploitcredentialprivates': MetasploitCredentialPrivates,
    'metasploitcredentialrealms': MetasploitCredentialRealms,
    'metasploitcredentiallogins': MetasploitCredentialLogins,
    'vulns': Vulns,
    'vulndetails': VulnDetails,
    'vulnattempts': VulnAttempts,
    'vulnsrefs': VulnsRefs,
    'refs': Refs
}


def create_filter_parser():
    # Базовые элементы
    lparen, rparen = map(Suppress, "()")
    lbrace, rbrace = map(Suppress, "{}")
    
    # Идентификаторы (имена таблиц и полей)
    identifier = Word(alphas + '_', alphanums + '_.')
    
    # Агрегатные функции
    aggregate_func = CaselessKeyword("COUNT") | CaselessKeyword("SUM") | CaselessKeyword("AVG") | \
                    CaselessKeyword("MIN") | CaselessKeyword("MAX")
    
    # Агрегатное выражение
    aggregate_expr = Group(aggregate_func + lparen + identifier + rparen)
    
    # Числовые значения
    integer = Word(nums).setParseAction(lambda t: int(t[0]))
    number = integer
    
    # IP-адреса с маской
    ip_address = Regex(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?')
    
    # Строковые значения
    string = QuotedString('"') | QuotedString("'")
    
    # NULL значения
    null_value = Keyword("null").setParseAction(lambda: None)
    
    # Списки значений (в фигурных скобках)
    list_item = number | string | ip_address | null_value
    list_value = Group(lbrace + delimitedList(list_item) + rbrace)
    
    # Значения (числа, строки, IP-адреса, списки, null)
    simple_value = number | string | ip_address | list_value | null_value
    
    # Операторы сравнения
    comp_op = oneOf("== != > < >= <=")
    like_op = oneOf("like ilike")
    in_op = Literal("in")
    is_op = oneOf("is isnot")
    
    # Базовое условие сравнения (без агрегатных функций)
    simple_condition = Group(
        identifier + comp_op + simple_value |
        identifier + like_op + simple_value |
        identifier + in_op + list_value |
        identifier + is_op + null_value
    )
    
    # Условие с агрегатными функциями
    aggregate_condition = Group(
        aggregate_expr + comp_op + simple_value
    )
    
    # Объединяем оба типа условий
    condition = simple_condition | aggregate_condition
    
    # Логические операторы
    and_op = Literal("&&")
    or_op = Literal("||")
    not_op = Literal("!")
    
    # Создаем выражение с помощью Forward для рекурсивного определения
    expr = Forward()
    factor = condition | Group(lparen + expr + rparen)
    expr << infixNotation(factor, [
        (not_op, 1, opAssoc.RIGHT),
        (and_op, 2, opAssoc.LEFT),
        (or_op, 2, opAssoc.LEFT),
    ])
    
    return expr

# Создаем парсер
filter_parser = create_filter_parser()

def normalize_filter_string(filter_str):
    """
    Нормализует строку фильтра для корректного парсинга
    """
    # Заменяем alias creds на нужные таблицы
    filter_str= filter_str.replace('creds.username', 'metasploitcredentialpublics.username')
    filter_str= filter_str.replace('creds.password', 'metasploitcredentialprivates.data')
    filter_str= filter_str.replace('creds.passwordtype', 'metasploitcredentialprivates.type')
    filter_str= filter_str.replace('creds.realm', 'metasploitcredentialrealms.value')
    filter_str= filter_str.replace('creds.realmtype', 'metasploitcredentialrealms.key')
    filter_str= filter_str.replace('creds.access_level', 'metasploitcredentiallogins.access_level')
    filter_str= filter_str.replace('vulns.name', 'vulns.name')
    filter_str= filter_str.replace('vulns.title', 'vulndetails.title')
    filter_str= filter_str.replace('vulns.description', 'vulndetails.description')
    filter_str= filter_str.replace('vulns.exploited', 'vulnattempts.exploited')
    filter_str= filter_str.replace('vulns.ref', 'refs.name')

    # Удаляем все пробелы вокруг операторов
    filter_str = re.sub(r'\s*([&|!])\s*', r'\1', filter_str)
    
    # Заменяем одиночные & и | на двойные
    #filter_str = re.sub(r'&(?!&)', '&&', filter_str)
    #filter_str = re.sub(r'\|(?!\|)', '||', filter_str)
    
    # Добавляем пробелы вокруг операторов
    #filter_str = re.sub(r'([&|!]{1,2})', r' \1 ', filter_str)
    
    # Удаляем лишние пробелы вокруг скобок
    filter_str = re.sub(r'\s*([{}()])\s*', r'\1', filter_str)
    
    # Заменяем множественные пробелы на один
    filter_str = re.sub(r'\s+', ' ', filter_str.strip())
    
    return filter_str


def parse_filter_string(filter_str):
    """
    Парсит строку фильтра и возвращает абстрактное синтаксическое дерево
    """
    try:
        # Нормализуем строку фильтра
        normalized_str = normalize_filter_string(filter_str)
        print(f"Нормализованная строка: '{normalized_str}'")
        
        result = filter_parser.parseString(normalized_str, parseAll=True)
        print(f"Результат парсинга: {result}")
        return result[0] if result else None
    except ParseException as e:
        print(f"Ошибка парсинга: {e}")
        raise ValueError(f"Ошибка парсинга фильтра: {e}")


def convert_to_sqlalchemy_filter(parsed_filter):
    """
    Преобразует абстрактное синтаксическое дерево в фильтры SQLAlchemy
    Возвращает кортеж: (where_conditions, having_conditions)
    """
    # Преобразуем ParseResults в список, если необходимо
    if isinstance(parsed_filter, ParseResults):
        parsed_filter = parsed_filter.asList()
    
    # Если это не список, значит это одиночное значение
    if not isinstance(parsed_filter, list):
        raise ValueError(f"Ожидался список, получен: {type(parsed_filter)} - {parsed_filter}")
    
    # Обработка унарных операторов
    if len(parsed_filter) == 2 and parsed_filter[0] == '!':
        right_where, right_having = convert_to_sqlalchemy_filter(parsed_filter[1])
        if right_where is not None and right_having is not None:
            # Если есть оба типа условий, мы не можем применить NOT к обоим
            raise ValueError("Невозможно применить оператор NOT к смешанным WHERE и HAVING условиям")
        elif right_where is not None:
            return (not_(right_where), None)
        else:
            return (None, not_(right_having))
    
    # Обработка цепочек операторов (более 3 элементов)
    if len(parsed_filter) > 3 and parsed_filter[1] in ('&&', '||'):
        # Находим позиции всех операторов в цепочке
        operator_positions = [i for i in range(1, len(parsed_filter), 2)]
        operators = [parsed_filter[i] for i in operator_positions]
        
        # Проверяем, что все операторы одинаковые
        if len(set(operators)) != 1:
            raise ValueError("Смешанные операторы в цепочке без скобок")
        
        operator = operators[0]
        
        # Разделяем условия и операторы
        conditions = [parsed_filter[i] for i in range(0, len(parsed_filter), 2)]
        
        # Рекурсивно обрабатываем все условия
        converted_conditions = [convert_to_sqlalchemy_filter(cond) for cond in conditions]
        
        # Разделяем условия на WHERE и HAVING
        where_conditions = [where for where, having in converted_conditions if where is not None]
        having_conditions = [having for where, having in converted_conditions if having is not None]
        
        # Комбинируем WHERE условия
        if where_conditions:
            if operator == '&&':
                where_condition = and_(*where_conditions)
            else:
                where_condition = or_(*where_conditions)
        else:
            where_condition = None
        
        # Комбинируем HAVING условия
        if having_conditions:
            if operator == '&&':
                having_condition = and_(*having_conditions)
            else:
                having_condition = or_(*having_conditions)
        else:
            having_condition = None
        
        return (where_condition, having_condition)
    
    # Обработка бинарных операторов
    elif len(parsed_filter) == 3:
        operator = parsed_filter[1]
        
        # Логические операторы
        if operator in ('&&', '||'):
            left_where, left_having = convert_to_sqlalchemy_filter(parsed_filter[0])
            right_where, right_having = convert_to_sqlalchemy_filter(parsed_filter[2])
            
            # Для AND и OR мы можем комбинировать условия разных типов
            # Создаем отдельные условия для WHERE и HAVING
            where_condition = None
            having_condition = None
            
            # Комбинируем WHERE условия
            if left_where is not None and right_where is not None:
                if operator == '&&':
                    where_condition = and_(left_where, right_where)
                else:
                    where_condition = or_(left_where, right_where)
            elif left_where is not None:
                where_condition = left_where
            elif right_where is not None:
                where_condition = right_where
            
            # Комбинируем HAVING условия
            if left_having is not None and right_having is not None:
                if operator == '&&':
                    having_condition = and_(left_having, right_having)
                else:
                    having_condition = or_(left_having, right_having)
            elif left_having is not None:
                having_condition = left_having
            elif right_having is not None:
                having_condition = right_having
            
            return (where_condition, having_condition)
        
        # Операторы сравнения
        else:
            left_operand = parsed_filter[0]
            operator = parsed_filter[1]
            right_operand = parsed_filter[2]
            
            # Обработка агрегатных функций в левой части
            if isinstance(left_operand, list) and left_operand[0] in ('COUNT', 'SUM', 'AVG', 'MIN', 'MAX'):
                func_name = left_operand[0]
                field_name = left_operand[1]
                
                # Получение модели и поля
                if '.' in field_name:
                    model_name, column_name = field_name.split('.', 1)
                    model = model_mapping.get(model_name.lower())
                    if not model:
                        raise ValueError(f"Модель {model_name} не найдена")
                    column = getattr(model, column_name, None)
                    if not column:
                        raise ValueError(f"Поле {column_name} не найдено в модели {model_name}")
                else:
                    # Если имя модели не указано, используем Hosts по умолчанию
                    column = getattr(model_mapping['hosts'], field_name, None)
                    if not column:
                        raise ValueError(f"Поле {field_name} не найдено в модели Hosts")
                
                # Создаем агрегатную функцию
                if func_name == 'COUNT':
                    agg_func = func.count(column)
                elif func_name == 'SUM':
                    agg_func = func.sum(column)
                elif func_name == 'AVG':
                    agg_func = func.avg(column)
                elif func_name == 'MIN':
                    agg_func = func.min(column)
                elif func_name == 'MAX':
                    agg_func = func.max(column)
                else:
                    raise ValueError(f"Неизвестная агрегатная функция: {func_name}")
                
                # Преобразование операторов для агрегатных функций
                if operator == '==':
                    return (None, agg_func == right_operand)
                elif operator == '!=':
                    return (None, agg_func != right_operand)
                elif operator == '>':
                    return (None, agg_func > right_operand)
                elif operator == '<':
                    return (None, agg_func < right_operand)
                elif operator == '>=':
                    return (None, agg_func >= right_operand)
                elif operator == '<=':
                    return (None, agg_func <= right_operand)
                else:
                    raise ValueError(f"Неизвестный оператор для агрегатной функции: {operator}")
            
            # Обработка обычных полей
            else:
                field_name = left_operand
                value = right_operand
                
                # Получение модели и поля
                if '.' in field_name:
                    model_name, column_name = field_name.split('.', 1)
                    model = model_mapping.get(model_name.lower())
                    if not model:
                        raise ValueError(f"Модель {model_name} не найдена")
                    column = getattr(model, column_name, None)
                    if not column:
                        raise ValueError(f"Поле {column_name} не найдено в модели {model_name}")
                else:
                    # Если имя модели не указано, используем Hosts по умолчанию
                    column = getattr(model_mapping['hosts'], field_name, None)
                    if not column:
                        raise ValueError(f"Поле {field_name} не найдено в модели Hosts")
                
                # Специальная обработка для NULL значений
                if value is None:
                    if operator == '==' or operator == 'is':
                        return (column.is_(None), None)
                    elif operator == '!=' or operator == 'isnot':
                        return (column.isnot(None), None)
                    else:
                        raise ValueError(f"Неизвестный оператор для NULL: {operator}")
                
                # Специальная обработка для полей типа inet
                if (field_name.endswith('.address') or field_name == 'address') and isinstance(value, str):
                    # Для полей address используем специальную обработку для типа inet
                    if operator == '==':
                        # Используем оператор <<= для проверки вхождения в сеть
                        return (column.op('<<=')(value), None)
                    elif operator == '!=':
                        # Используем оператор >> для проверки невхождения в сеть
                        return (column.op('>>')(value), None)
                    # Для других операторов используем стандартную обработку
                
                # Преобразование значений для оператора IN
                if operator == 'in':
                    if not isinstance(value, list):
                        value = [value]
                    # Преобразуем строковые числа в числа
                    converted_values = []
                    for v in value:
                        if isinstance(v, str) and v.isdigit():
                            converted_values.append(int(v))
                        else:
                            converted_values.append(v)
                    value = converted_values
                    return (column.in_(value), None)
                
                # Преобразование операторов
                if operator == '==':
                    return (column == value, None)
                elif operator == '!=':
                    return (column != value, None)
                elif operator == '>':
                    return (column > value, None)
                elif operator == '<':
                    return (column < value, None)
                elif operator == '>=':
                    return (column >= value, None)
                elif operator == '<=':
                    return (column <= value, None)
                elif operator == 'like':
                    return (column.like(value), None)
                elif operator == 'ilike':
                    return (column.ilike(value), None)
                else:
                    raise ValueError(f"Неизвестный оператор: {operator}")
    
    else:
        raise ValueError(f"Неожиданная структура фильтра: {parsed_filter}")


def apply_dynamic_filters(query, filter_str):
    """
    Применяет динамические фильтры к запросу SQLAlchemy
    """
    if not filter_str or filter_str.strip() == '':
        query = query.group_by(Hosts.id).order_by(Hosts.address)
        return query
    
    try:
        # Удаляем лишние пробелы для улучшения парсинга
        filter_str = re.sub(r'\s+', ' ', filter_str.strip())
        parsed = parse_filter_string(filter_str)
        if parsed is None:
            return query
            
        where_condition, having_condition = convert_to_sqlalchemy_filter(parsed)
        
        # Применяем WHERE условие
        if where_condition is not None:
            query = query.filter(where_condition)
        
        query = query.group_by(Hosts.id)

        # Применяем HAVING условие
        if having_condition is not None:
            query = query.having(having_condition)

        query = query.order_by(Hosts.address)
        
        return query
    except Exception as e:
        traceback.print_exc()
        raise ValueError(f"Ошибка применения фильтров: {str(e)}")