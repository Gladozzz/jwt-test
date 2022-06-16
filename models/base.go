package models

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var db *DB

type DB struct {
	client *mongo.Client
}

func (_db *DB) getAccountByUid(uid string) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": uid}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Printf("getAccountByUid err: %v\n", err)
		return nil, err
	} else {
		return &result, nil
	}
}

func (_db *DB) getAccountByLogin(login string) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"login": login}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Printf("getAccountByLogin err: %v\n", err)
		return nil, err
	} else {
		return &result, nil
	}
}

func (_db *DB) addTokenToAccount(tp TokenPair) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	filter := bson.M{"id": tp.UserId}
	update := bson.M{"$push": bson.M{"tokens": tp}}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("addTokenToAccount err")
		log.Println(err)
		return err
	} else {
		fmt.Println("addTokenToAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) RemoveTokenFromAccount(userId, atId, rtId uuid.UUID) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	filter := bson.M{"tokens": bson.M{"$elemMatch": bson.M{"userid": userId, "accessuuid": atId, "refreshuuid": rtId}}}
	update := bson.M{"$pull": bson.M{"tokens": bson.M{"userid": userId, "accessuuid": atId, "refreshuuid": rtId}}}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Printf("RemoveTokenFromAccount can't find account with userId: %v atId: %v rtId: %v\n", userId, atId, rtId)
		return err
	} else {
		fmt.Println("RemoveTokenFromAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) deleteAllTokensFromAccount(lf LoginForm) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"login": lf.Login}
	update := bson.D{
		{"$set", bson.D{
			{"tokens", []TokenPair{}},
		}},
	}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Printf("deleteAllTokensFromAccount err: %v\n", err)
		return err
	} else {
		fmt.Println("deleteAllTokensFromAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) refreshTokenPair(rt []byte) (*string, *string, error) {
	userID, err := getUserIdFromRefreshToken(string(rt))
	if err != nil {
		return nil, nil, err
	}
	log.Printf("refreshTokenPair userID:\n%v\nrt:\n%v\n", userID, string(rt))
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": userID}
	var result Account
	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil && err.Error() != "mongo: no documents in result" {
		log.Printf("refreshTokenPair err: %v\n", err)
		return nil, nil, err
	} else if err != nil && err.Error() == "mongo: no documents in result" {
		log.Printf("There is no user with this id: %v\n", userID)
		return nil, nil, errors.New("There is no user with this id")
	}
	log.Printf("refreshTokenPair result acc id: %v\n", userID)
	for _, token := range result.Tokens {
		rtHashed := token.HashedRefreshToken
		log.Printf("rtHashed: %v", token.RefreshToken)
		err = bcrypt.CompareHashAndPassword(rtHashed, rt)
		if err == nil {
			newTP, atString, rtString, err := CreateToken(result.ID)
			if err != nil {
				log.Println("refreshTokenPair err in CreateToken")
				return nil, nil, err
			}
			var filter = bson.M{"tokens": bson.M{"$elemMatch": bson.M{"accessuuid": token.AccessUuid}}, "id": result.ID}
			update := bson.D{
				{"$set", bson.D{
					{"tokens.$.atexpires", newTP.AtExpires},
					{"tokens.$.accessuuid", newTP.AccessUuid},
					{"tokens.$.refreshuuid", newTP.RefreshUuid},
					{"tokens.$.rtexpires", newTP.RtExpires},
					{"tokens.$.hashedrefreshtoken", newTP.HashedRefreshToken},
				}},
			}
			updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
			if err != nil {
				log.Println("refreshTokenPair err")
				log.Println(err)
				return nil, nil, err
			} else {
				fmt.Println("refreshTokenPair updated result ", updateResult.UpsertedID)
				return atString, rtString, nil
			}
		} else {
			log.Printf("refreshTokenPair CompareHashAndPassword err: %v\n", err)
		}
	}
	err = errors.New("There is no refresh token of this user")
	fmt.Printf("refreshTokenPair There is no refresh token of this user:\n%v\n", err)
	return nil, nil, err
}

func (_db *DB) ValidAccessToken(atUUID, rtUUID, userId uuid.UUID) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"tokens": bson.M{"$elemMatch": bson.M{"userid": userId, "accessuuid": atUUID, "refreshuuid": rtUUID}}}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Printf("ValidAccessToken can't find out account with access token err: %v\n", err)
		return nil, err
	}
	return &result, nil
}

func (_db *DB) putAccount(ac Account) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	insertResult, err := collection.InsertOne(context.TODO(), ac)
	if err != nil {
		log.Printf("putAccount err: Can't insert account: %v\n", err)
		return err
	}
	fmt.Println("Inserted a single document: ", insertResult.InsertedID)
	return nil
}

func (_db *DB) removeAccountByID(UserId string) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": UserId}
	deleteResult, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		log.Printf("removeAccountByID err Can't remove account: %v\n", err)
		return err
	} else {
		fmt.Println("Deleted a single document: ", deleteResult.DeletedCount)
		return nil
	}
}

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

//func getUserIdFromAccessToken(tokenString string) (*string, error) {
//	return getUserIdFromToken(tokenString, func(token *jwt.Token) (interface{}, error) {
//		return []byte(os.Getenv("ACCESS_SECRET")), nil
//	})
//}
func getUserIdFromRefreshToken(tokenString string) (*uuid.UUID, error) {
	return getUserIdFromToken(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
}
func getUserIdFromToken(tokenString string, keyfunc jwt.Keyfunc) (*uuid.UUID, error) {
	//tk := &Token{}
	token, err := jwt.Parse(tokenString, keyfunc)
	if err != nil {
		log.Println("getUserIdFromToken err")
		log.Println(err)
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userId, ok := claims["user_id"].(string)
		if !ok {
			err = errors.New("jwt.Claims is not valid")
			return nil, err
		}
		userIdAsUUID, err := uuid.Parse(userId)
		if err != nil {
			log.Printf("getUserIdFromToken: uuid.Parse err:\n%v\n", err)
			return nil, err
		}
		return &userIdAsUUID, nil
	}
	err = errors.New("token is not valid")
	fmt.Println("getUserIdFromToken err")
	fmt.Println(err)
	return nil, err
}

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Fatal("No .env file found")
	}
	db = new(DB)

	username := os.Getenv("ATLAS_USERNAME")
	password := os.Getenv("ATLAS_PASSWORD")
	if username == "" || password == "" {
		log.Fatal("Cannot get env variables from .env file")
	}
	uri := "mongodb+srv://" + username + ":" + password + "@main.dqx79.mongodb.net/?retryWrites=true&w=majority"
	log.Printf("db uri:%v", uri)

	_client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(
		uri,
	))
	if err != nil {
		log.Fatal(err)
	}
	db.client = _client
}

func GetDB() *DB {
	return db
}
