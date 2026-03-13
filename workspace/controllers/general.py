import json

#Десериализация объекта в формате JSON
def JSON_deserialize(data: str) -> dict:
    d = None
    try:
        json_acceptable_string = data.replace("'", "\"")
        d = json.loads(json_acceptable_string)
    except Exception as e:
        d = json.loads(data)
    return d

#Заполнение пустых строк словаря значениями None
def Dict_None(data: dict) -> dict:
    #Если есть пустые '' записи, то делаем его None
    for row in data:
        if(data[row] == ''):
            data[row] = None
    return data