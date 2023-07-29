from flask import Response
from werkzeug.datastructures import Headers
import json

class Json_Response:
    
    def __init__(self) -> None:
        self.mimetype: str = 'application/json'
        self.content_type: str = 'application/json'
        self.status: int = 200
        self.error_message: str = ''
        self.message: str = ''
        self.json: json = {}
        self.header: Headers = Headers()
    
    def addHeader(self, key: str, value: str):
        self.header.add(key, value)
        
    def response(self) -> Response:
        self.addHeader("error_message", self.error_message)
        self.addHeader("message", self.message)
        return Response(self.json, self.status, self.header, self.mimetype, self.content_type, False)
        
        
        
    
        
        
        