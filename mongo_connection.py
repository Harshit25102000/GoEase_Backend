import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")

# from pymongo.mongo_client import MongoClient
# from pymongo.server_api import ServerApi
# import urllib
# print("ss")
# uri = "mongodb+srv://<username>:"+urllib.parse.quote(<password>)+"@cluster0.xbhhod6.mongodb.net/?retryWrites=true&w=majority"
#
# # Create a new client and connect to the server
# client = MongoClient(uri, server_api=ServerApi('1'))
# print(client)
# try:
#     client.admin.command('ping')
#     print("Pinged your deployment. You successfully connected to MongoDB!")
# except Exception as e:
#     print(e)

db = client['GoEase']
student_credentials = db['student_credentials']