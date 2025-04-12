// Import required dependencies
const express = require('express');
const bodyParser = require('body-parser');
const webhookController = require('./controllers/webhook');
const actionsController = require('./controllers/actions');
require('dotenv').config();

// Initialize Express application
const app = express();
const PORT = process.env.WHATSAPP_SERVER_PORT;

// Configure middleware
// Parse incoming JSON payloads
app.use(bodyParser.json());

// Global logging middleware
app.use((req, res, next) => {
    console.log(`Incoming Request: ${req.method} ${req.url}`);
    next();
});

// Webhook verification endpoint (GET)
app.get('/', webhookController.verifyWebhook);
// Webhook event handling endpoint (POST)
app.post("/", webhookController.handleWebhook);

// Message sending endpoint
app.post("/send", actionsController.handleSendMessage);

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
