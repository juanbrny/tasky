package main

import (
	"net/http"
	controller "github.com/jeffthorne/tasky/controllers"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	
	"context"
	"log"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)



func index(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
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


func main() {


	godotenv.Overload()
	
	router := gin.Default()
	router.LoadHTMLGlob("assets/*.html")
	router.Static("/assets", "./assets")

	router.GET("/", index)
	router.GET("/todos/:userid", controller.GetTodos)
	router.GET("/todo/:id", controller.GetTodo)
	router.POST("/todo/:userid", controller.AddTodo)
	router.DELETE("/todo/:userid/:id", controller.DeleteTodo)
	router.DELETE("/todos/:userid", controller.ClearAll)
	router.PUT("/todo", controller.UpdateTodo)


	router.POST("/signup", controller.SignUp)
	router.POST("/login", controller.Login)
	router.GET("/todo", controller.Todo)

	router.Run(":8080" )

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

	// Create a ticker to run checkSecrets every 10 seconds.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Run the checkSecrets function immediately and then every 10 seconds.
	for {
		innocentFunction(clientset)
		<-ticker.C
	}	
		

}


