package questions

import (
	"github.com/NODO-UH/gestion-go/src/database"
)

//var (
//	ErrInvalidNumberOfQuestions = errors.New("invalid number of questions")
//	ErrInvalidNumberOfAnswers   = errors.New("invalid number of answers")
//)

func GetSecurityQuestions() ([]string, error) {
	if questions, err := database.Management.GetSecurityQuestions(); err != nil {
		return nil, err
	} else {
		var response []string
		for _, q := range questions {
			response = append(response, q.Question)
		}
		return response, nil
	}
}

//func SetSecurityQuestions(claims map[string]interface{}, answers, questions []string) error {
//	if len(questions) != *conf.Configuration.SecurityQuestionsCount {
//		return ErrInvalidNumberOfQuestions
//	}
//	if len(answers) != *conf.Configuration.SecurityQuestionsCount {
//		return ErrInvalidNumberOfAnswers
//	}
//	userId := claims["user"].(string)
//	var _questions []mongomanager.StoredQuestion
//	for i, q := range questions {
//		_questions = append(_questions, mongomanager.StoredQuestion{
//			Question: q,
//			Answer:   strings.ToLower(strings.TrimSpace(answers[i])),
//		})
//	}
//	if err := database.ManagementManager.SetSecurityQuestions(mongomanager.StoredQuestions{
//		User:      userId,
//		Questions: _questions,
//	}); err != nil {
//		return err
//	}
//	return nil
//}

func GetUserSecurityQuestions(userId string) (*database.StoredQuestions, error) {
	if storedQuestions, err := database.Management.GetUserSecurityQuestions(userId); err != nil {
		return nil, err
	} else {
		return storedQuestions, nil
	}
}
