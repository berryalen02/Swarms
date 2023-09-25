package kafka

import (
	"fmt"

	"github.com/IBM/sarama"
)

var (
	Broker string = "192.168.29.144:9092"
	Topic  string = "quickstart-events"
)

func MessageInit() (msg *sarama.ProducerMessage) {
	message := &sarama.ProducerMessage{}
	return message
}

func Producer2Kafka(broker string, topic string, result string) (err error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Partitioner = sarama.NewRandomPartitioner
	config.Producer.Return.Successes = true

	msg := MessageInit()
	msg.Topic = topic
	msg.Value = sarama.StringEncoder(result)

	//异步连接kafka
	client, err := sarama.NewSyncProducer([]string{broker}, config)
	if err != nil {
		fmt.Println("producer closed,err:", err)
		return err
	}
	defer client.Close()

	//发送消息
	brokerid, offset, err := client.SendMessage(msg)
	if err != nil {
		fmt.Println("send msg failed, err:", err)
		return err
	}
	fmt.Printf("topic:%v,brokerid:%v offset:%v\n", topic, brokerid, offset)
	return nil
}
