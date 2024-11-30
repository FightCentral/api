import getEnv from "@/utils/env";
import amqp, { Channel, Connection } from 'amqplib';

class RabbitMQClient {
    private static instance: RabbitMQClient;
    private connection: Connection | null = null;
    private channel: Channel | null = null;

    private constructor() {}

    public static getInstance(): RabbitMQClient {
        if (!RabbitMQClient.instance) {
            RabbitMQClient.instance = new RabbitMQClient();
        }
        return RabbitMQClient.instance;
    }

    async connect(): Promise<void> {
        try {
            this.connection = await amqp.connect(getEnv("AMQP_URL", 'amqp://localhost:5672'));
            this.channel = await this.connection.createChannel();
            console.log('Connected to RabbitMQ');
        } catch (error) {
            console.error('RabbitMQ connection error:', error);
            throw error;
        }
    }

    async publishMessage(queue: string, message: any): Promise<void> {
        try {
            if (!this.channel)
                throw new Error('Channel is not initialized');

            await this.channel.assertQueue(queue, { durable: true });
            this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)));
            console.log(`Message sent to queue ${queue}:`, message);
        } catch (error) {
            console.error('Error publishing message:', error);
            throw error;
        }
    }

    async consumeMessages(queue: string, callback: (message: any) => void): Promise<void> {
        try {
            if (!this.channel)
                throw new Error('Channel is not initialized');

            await this.channel.assertQueue(queue, { durable: true });
            console.log(`Waiting for messages from queue ${queue}`);

            this.channel.consume(queue, (message) => {
                if (message) {
                    const content = JSON.parse(message.content.toString());
                    callback(content);
                    this.channel?.ack(message);
                }
            });
        } catch (error) {
            console.error('Error consuming messages:', error);
            throw error;
        }
    }

    async closeConnection(): Promise<void> {
        try {
            await this.channel?.close();
            await this.connection?.close();
            console.log('RabbitMQ connection closed');
        } catch (error) {
            console.error('Error closing connection:', error);
            throw error;
        }
    }
}

export const rabbitMQClient = RabbitMQClient.getInstance();