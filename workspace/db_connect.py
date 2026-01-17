from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from workspace.models.migration import create_tables
import configparser

#Read config file
config = configparser.ConfigParser()
config.read('.\\config.ini')
db_string = "postgresql://{login}:{password}@{address}:{port}/{db}".format(login=config.get("DB", "login"),
                                                                           password=config.get("DB", "password"),
                                                                           address=config.get("DB", "address"),
                                                                           port=config.get("DB", "port"),
                                                                           db=config.get("DB", "db"))

db = create_engine(db_string, echo=True)
meta = MetaData(schema="public")  
create_tables(db)

#Функция создания сессии
def create_session():
    return Session(db)