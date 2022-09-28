using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;


namespace JWTAuth.WebApi.Models
{
    public class User
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string id { get; set; }
       
        [BsonElement("name")]
        public string name { get; set; }
      
        [BsonElement("email")]  
        public string email { get; set; }

        [BsonElement("password")]
        public string password { get; set; }

        [BsonElement("salt")]
        public string salt { get; set; }


        [BsonElement("refreshToken")]
        public string refreshToken { get; set; }


    }
}
