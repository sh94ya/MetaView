import configparser
import workspace.logger as logging

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from workspace.models.migration import UserTasks, UserTasksPerformers, Users, Workspaces

"""
Контроллер для взаимодействия с моделями: UserTasks, UserTaskStatus, UserTasksPerformers.
В части реализации раздела ПЛАНИРОВАНИЕ и УПРАВЛЕНИЕ_ЗАДАЧАМИ.

Используются следующие сокращения:
- UserTasks -> Task(s)
- UserTaskStatus -> Status
- UserTasksPerformers -> Performer(s)

Реализованы функции:
- add_task(db_session, data) - добавление новой задачи пользователей.
- get_all_status(db_session) - получение списка всех доступных статусов выполнения задач пользователей.
- get_all_users(db_session) - получение списка всех зарегестрированных пользователей (модель Users).
- get_full_info_about_current_tasks(db_session, task_id) - получение полной информации по конкретной задачи пользователей.
- get_full_info_about_all_tasks(db_session, workspace_id) - получение полной информации о всех задачах пользователей в
заданной рабочей области.
- del_tasks(db_session, tasks_ids) - удаление списка задач пользователей.
- edit_task(db_session, task_id, data) - редактирование задачи пользователей.
"""


log = logging.getLogger()


def __add_performers(db_session: Session, task_id: str, performer_id: str):
    if not str(task_id).isdigit() or not str(performer_id).isdigit():
        log.error("Введенное значение не является числовым идентификатором (task_id - {0}, "
                  "performer_id - {1}).".format(task_id, performer_id))
        raise ValueError

    performer = UserTasksPerformers(task_id, performer_id)
    db_session.add(performer)


def __get_performers(db_session: Session, task_id: str) -> list:
    try:
        if not str(task_id).isdigit():
            log.error("Введенное значение не является числовым идентификатором (task_id - {0}).".format(task_id))
            raise ValueError

        performers = []

        for performer_object in db_session.query(UserTasksPerformers, Users).join(Users).filter(UserTasksPerformers.user_task_id == task_id):

            performer_dict = {"id":         performer_object[1].id,
                              "label":   performer_object[1].username,
                              "username":   performer_object[1].username,
                              "fullname":   performer_object[1].fullname}

            performers.append(performer_dict)

        return performers

    except Exception as e:
        log.error("Ошибка при обращении к моделям UserTasksPerformers, Users (task_id - {0}).".format(task_id))


def __get_task(db_session: Session, task_id: str) -> UserTasks:
    if not str(task_id).isdigit():
        log.error("Введенное значение не является числовым идентификатором (task_id - {0}).".format(task_id))
        raise ValueError
    query = select(UserTasks).where(UserTasks.id == int(task_id))
    task = db_session.scalar(query)

    return task


def __get_all_tasks(db_session: Session, workspace_id: str) -> list:
    if not str(workspace_id).isdigit():
        log.error("Введенное значение не является числовым идентификатором (workspace_id - {0}).".format(workspace_id))
        raise ValueError
    tasks = []
    for task in db_session.query(UserTasks).filter(UserTasks.workspace_id == workspace_id):
        tasks.append(task)
    return tasks


def add_task(db_session: Session, workspace: int, data: dict) -> int:
    try:
        task = UserTasks(workspace, data["name"])
        db_session.add(task)
        task.update_state(data)
        db_session.flush()

        for performer in data["performers"]:
            __add_performers(db_session, task.id, performer['id'])
        
        db_session.commit()
        return {'status': 200, 'id': task.id}
    except Exception as e:
        log.error("Error in controllers `UserTasksController` function  `add_task`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


# def get_all_status(db_session: Session) -> list:
#     """
#     Функция получения информации о всех доступных статусах задач пользователей (модель UserTaskStatus).

#     Возвращаемым значением является СПИСОК словарей следующей структуры:
#     id - уникальный идентификатор статуса задачи пользователей.
#     name - наименование статуса задачи пользователей.
#     """

#     statuses = []

#     for status_object in db_session.query(UserTaskStatus):
#         statuses_dict = {"id":   status_object.id,
#                          "name": status_object.name}

#         statuses.append(statuses_dict)

#     return statuses


def get_all_users(db_session: Session) -> list:
    users = []
    for user_object in db_session.query(Users):
        user_dict = {"id":          user_object.id,
                     "username":    user_object.username,
                     "fullname":    user_object.fullname}
        users.append(user_dict)
    return users


def get_full_info_about_current_tasks(db_session: Session, task_id: str) -> dict:
    try:
        if not str(task_id).isdigit():
            log.error("Введенное значение не является числовым идентификатором (task_id - {0}).".format(task_id))
            raise ValueError
        task_object = __get_task(db_session, task_id)
        performers = __get_performers(db_session, task_object.id)
        workspace = db_session.query(Workspaces).filter(Workspaces.id == task_object.workspace_id)
        status_name = db_session.query(UserTaskStatus).filter(UserTaskStatus.id == task_object.status_id)
        task_dict = {"id":              task_object.id,
                     "name":            task_object.name,
                     "description":     task_object.description,
                     "final_date":      task_object.final_date,
                     "status_id":       task_object.status_id,
                     "workspace_id":    task_object.workspace_id,
                     "workspace_name":  workspace[0].name,
                     "performers":      performers,
                     "status_name":     status_name[0].name}
        return task_dict
    except Exception as e:
        log.error("Ошибка при получении полной информации о задаче пользователей (task_id - {0}).".format(task_id))
        raise


def get_full_info_about_all_tasks(db_session: Session, workspace_id: str) -> list:
    try:
        if not str(workspace_id).isdigit():
            log.error("Введенное значение не является числовым идентификатором (task_id - {0}).".format(workspace_id))
            raise ValueError
        tasks_list = []
        workspace = db_session.query(Workspaces).filter(Workspaces.id == workspace_id)
        tasks_objects = __get_all_tasks(db_session, workspace_id)
        for task in tasks_objects:
            performers = __get_performers(db_session, task.id)
            # status_name = db_session.query(UserTaskStatus).filter(UserTaskStatus.id == task.status_id)
            task_dict = {"id":               task.id,
                         "name":             task.name,
                         "description":      task.description,
                         "final_date":       task.final_date,
                         "status":        task.status,
                         "workspace_id":     task.workspace_id,
                         "workspace_name":   workspace[0].name,
                         "performers":       performers,
                        #  "status_name":      status_name[0].name
                         }
            tasks_list.append(task_dict)
        return tasks_list
    except Exception as e:
        log.error("Ошибка при получении полной информации о всех задачах пользователей в указанной рабочей области "
                      "(workspace_id - {0}).".format(workspace_id))
        raise


def del_tasks(db_session: Session, workspace: int, tasks_ids: list) -> bool:
    res = {'status': 410,'message':'Не удалось удалить запись!'}
    try:
        log.info("Запущен процесс удаления задач пользователей (tasks_ids - {0}).".format(tasks_ids))
        for task_id in tasks_ids:
            if not str(task_id).isdigit():
                log.error("Как минимум одно из введенных значений не является числовым "
                          "идентификатором (task_ids - {0}).".format(tasks_ids))
                raise ValueError

            task_object = (db_session.query(UserTasks).filter(UserTasks.id == task_id).one())
            db_session.delete(task_object)
        db_session.commit()
        log.info("Удаление задач пользователей упешно завершено (tasks_ids - {0}).".format(tasks_ids))
        res = {'status': 200}
    except Exception as e:
        log.error("Ошибка при удалении задач пользователей (tasks_ids - {0}).".format(tasks_ids))
        db_session.rollback()
    return res


def edit_task(db_session: Session, workspace: int, data: dict) -> int:
    res = {'status':410,'message':'Не удалось удалить запись!'}
    try:
        log.info("Запущен процесс редактирования задачи пользователей (data - {0}).".format(data))
        db_session.query(UserTasks).filter_by(id = data['id']).update(
                    {'name': data["name"],
                    'final_date': data["final_date"],
                    'workspace_id': workspace,
                    'status': data["status"],
                    'description': data["description"]})
        db_session.flush()
        db_session.query(UserTasksPerformers).filter_by(user_task_id = data["id"]).delete()
        db_session.flush()
        for performer in data["performers"]:
            __add_performers(db_session, data["id"], performer['id'])
        db_session.flush()
        db_session.commit()
        res = {'status':200}
    except Exception as e:
        db_session.rollback()
        log.error("Ошибка редактирования задачи пользователей (data - {0}).".format(data))
    return res
