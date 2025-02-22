import sqlite3
import json
from flask import g

class DataBase:
    def __init__(self, path: str) -> None:
        self.path = path

    def _get_connection(self):
        if 'db_connection' not in g:
            g.db_connection = sqlite3.connect(self.path, check_same_thread=False)  # Разрешаем использование в разных потоках
        return g.db_connection

    def get(self, key):
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT value FROM data WHERE key = ?', (key,))
        result = cursor.fetchone()
        return json.loads(result[0]) if result else None  # Десериализация словаря
    
    def set(self, key, value) -> None:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute('REPLACE INTO data (key, value) VALUES (?, ?)', (key, json.dumps(value)))  # Сериализация словаря
        connection.commit()
    
    def exists(self, key) -> bool:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT 1 FROM data WHERE key = ?', (key,))
        return cursor.fetchone() is not None
    
    def all(self) -> dict:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT key, value FROM data')
        return {key: json.loads(value) for key, value in cursor.fetchall()}  # Десериализация всех значений

    def close(self):
        db_connection = g.pop('db_connection', None)
        if db_connection is not None:
            db_connection.close()
