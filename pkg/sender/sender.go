package sender

type EmailSenderServer struct {
}

func NewEmailSenderServer() *EmailSenderServer {
	return &EmailSenderServer{}
}

func (e *EmailSenderServer) Send(email, msg string) error {
	return nil
}
