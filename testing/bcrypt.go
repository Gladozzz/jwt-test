package testing

import (
	"jwt-test/models"
	"log"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestBcrypt() {
	userId := uuid.New()
	tp, _, rt, _ := models.CreateToken(userId)
	log.Printf("testBcrypt: %v\n%v\n", string(tp.HashedRefreshToken), *rt)
	err := bcrypt.CompareHashAndPassword(tp.HashedRefreshToken, []byte(*rt))
	log.Printf("testBcrypt: %v\n", err)
	// models.GetDB().
}
