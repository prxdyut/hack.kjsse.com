require('dotenv').config();
const axios = require('axios');

// WhatsApp API configuration
const WHATSAPP_API_VERSION = 'v22.0'; // Using a stable version
const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_ID;
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;

class WhatsAppActionsController {
    /**
     * HTTP handler for sending custom messages
     * 
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     */
    static async handleSendMessage(req, res) {
        try {
            const { to, message, languageCode = 'en_US' } = req.body;

            if (!to) {
                return res.status(400).json({ error: 'Recipient phone number (to) is required' });
            }

            let response;

            if (!message) {
                return res.status(400).json({ error: 'Message text is required for text messages' });
            }
            response = await WhatsAppActionsController.sendTextMessage(to, message);

            res.status(200).json(response);
        } catch (error) {
            console.error('Error in handleSendMessage:', error);
            res.status(500).json({
                error: 'Failed to send message',
                details: error.response?.data || error.message
            });
        }
    }

    /**
     * Sends a text message using the WhatsApp Cloud API
     * 
     * @param {string} to - Recipient's phone number
     * @param {string} text - Message text to send
     * @returns {Promise} Response from WhatsApp API
     */
    static async sendTextMessage(to, text) {
        try {
            const url = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${PHONE_NUMBER_ID}/messages`;

            const response = await axios({
                method: 'POST',
                url: url,
                headers: {
                    'Authorization': `Bearer ${ACCESS_TOKEN}`,
                    'Content-Type': 'application/json',
                },
                data: {
                    messaging_product: 'whatsapp',
                    recipient_type: 'individual',
                    to: to,
                    type: 'text',
                    text: {
                        body: text
                    }
                }
            });

            console.log('Message sent successfully:', response.data);
            return response.data;
        } catch (error) {
            console.error('Error sending message:', error.response?.data || error.message);
            throw error;
        }
    }
}

module.exports = WhatsAppActionsController;
