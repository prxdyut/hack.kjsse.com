require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const mime = require('mime-types');

// WhatsApp verification token from environment variables
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const TEMP_DIR = path.join(__dirname, '../../temp');

// Create temp directory if it doesn't exist
if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
}

const WhatsAppActionsController = require('./actions');

class WhatsappWebhookController {
    /**
     * Handles webhook verification requests from WhatsApp.
     * WhatsApp sends a GET request with a challenge that needs to be echoed back
     * to verify the webhook endpoint.
     * 
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     */
    static verifyWebhook(req, res) {
        let mode = req.query['hub.mode'];
        let token = req.query['hub.verify_token'];
        let challenge = req.query['hub.challenge'];

        console.log(`Webhook Verification - Mode: ${mode}, Token: ${token}, Challenge: ${challenge}`);

        if (mode && token === ACCESS_TOKEN) {
            console.log('WEBHOOK_VERIFIED');
            res.status(200).send(challenge);
        } else {
            console.log('WEBHOOK_VERIFICATION_FAILED');
            res.sendStatus(403);
        }
    }

    /**
     * Get file extension from MIME type or filename
     * @param {string} mimeType - MIME type of the file
     * @param {string} filename - Original filename if available
     * @param {string} mediaType - Type of media (audio, image, video, document)
     * @returns {string} File extension with dot
     */
    static getFileExtension(mimeType, filename, mediaType) {
        // If we have a filename with extension, use that
        if (filename && path.extname(filename)) {
            return path.extname(filename);
        }

        // Try to get extension from mime-type
        if (mimeType) {
            const ext = mime.extension(mimeType);
            if (ext) return `.${ext}`;
        }

        // Fallback extensions based on media type
        const fallbackExtensions = {
            audio: '.ogg',
            voice: '.ogg',
            image: '.jpg',
            video: '.mp4',
            document: '.bin',
            sticker: '.webp'
        };

        return fallbackExtensions[mediaType] || '';
    }

    /**
     * Get safe filename
     * @param {string} mediaId - Media ID
     * @param {string} originalFilename - Original filename if available
     * @param {string} extension - File extension
     * @returns {string} Safe filename
     */
    static getSafeFilename(mediaId, originalFilename, extension) {
        let filename = '';
        
        if (originalFilename) {
            // Remove extension from original filename if it exists
            filename = path.basename(originalFilename, path.extname(originalFilename));
            // Replace unsafe characters
            filename = filename.replace(/[^a-zA-Z0-9-_]/g, '_');
        }

        // If no valid filename was created, use mediaId
        if (!filename) {
            filename = mediaId;
        }

        // Ensure filename is not too long
        if (filename.length > 200) {
            filename = filename.substring(0, 200);
        }

        return `${filename}${extension}`;
    }

    /**
     * Downloads a media file from WhatsApp API
     * @param {Object} mediaInfo - Media information object
     * @param {string} mediaType - Type of media
     * @returns {Promise<Object>} Object containing file path and metadata
     */
    static async downloadMedia(mediaInfo, mediaType) {
        try {
            const mediaId = mediaInfo.id;
            console.log(`Attempting to download ${mediaType} with ID: ${mediaId}`);

            // First, get the media URL
            const mediaUrl = `https://graph.facebook.com/v18.0/${mediaId}`;
            console.log('Fetching media URL from:', mediaUrl);

            const mediaResponse = await axios.get(mediaUrl, {
                headers: {
                    'Authorization': `Bearer ${ACCESS_TOKEN}`
                }
            });

            console.log('Media metadata response:', JSON.stringify(mediaResponse.data, null, 2));

            if (!mediaResponse.data.url) {
                throw new Error('No download URL received from WhatsApp API');
            }

            // Download the actual media file
            console.log('Downloading media from URL:', mediaResponse.data.url);
            const mediaFileResponse = await axios({
                method: 'GET',
                url: mediaResponse.data.url,
                headers: {
                    'Authorization': `Bearer ${ACCESS_TOKEN}`,
                    'Accept': '*/*'
                },
                responseType: 'arraybuffer',
                maxContentLength: 100 * 1024 * 1024 // 100MB max
            });

            const contentType = mediaFileResponse.headers['content-type'];
            console.log(`Downloaded media file size: ${mediaFileResponse.data.length} bytes, type: ${contentType}`);

            // Get file extension
            const extension = this.getFileExtension(
                contentType,
                mediaInfo.filename, // For documents
                mediaType
            );

            // Generate safe filename
            const filename = this.getSafeFilename(mediaId, mediaInfo.filename, extension);
            const filePath = path.join(TEMP_DIR, filename);

            // Ensure temp directory exists
            if (!fs.existsSync(TEMP_DIR)) {
                fs.mkdirSync(TEMP_DIR, { recursive: true });
            }

            // Save the file
            console.log('Saving file to:', filePath);
            fs.writeFileSync(filePath, mediaFileResponse.data);

            // Verify file was created
            if (fs.existsSync(filePath)) {
                const stats = fs.statSync(filePath);
                console.log(`Verified file creation - Size: ${stats.size} bytes`);
                
                return {
                    path: filePath,
                    filename: filename,
                    size: stats.size,
                    mimeType: contentType,
                    extension: extension,
                    mediaType: mediaType
                };
            } else {
                throw new Error('File was not created successfully');
            }
        } catch (error) {
            console.error(`Error downloading ${mediaType}:`, {
                message: error.message,
                response: error.response?.data,
                status: error.response?.status,
                headers: error.response?.headers
            });
            throw error;
        }
    }

    /**
     * Process location data and return formatted string
     * @param {Object} location - Location object from WhatsApp
     * @returns {string} Formatted location string
     */
    static formatLocation(location) {
        return `Location received:
Latitude: ${location.latitude}
Longitude: ${location.longitude}
${location.name ? `Name: ${location.name}` : ''}
${location.address ? `Address: ${location.address}` : ''}`;
    }

    /**
     * Format contacts data for readable message
     * @param {Array} contacts - Array of contact objects
     * @returns {string} Formatted contacts string
     */
    static formatContacts(contacts) {
        return contacts.map(contact => {
            const phones = contact.phones?.map(phone => phone.phone).join(', ') || 'No phone';
            return `Contact:
Name: ${contact.name.formatted_name}
Phones: ${phones}`;
        }).join('\n\n');
    }

    /**
     * Handles incoming messages from WhatsApp.
     * Simply logs the incoming webhook data.
     * 
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     */
    static async handleWebhook(req, res) {
        try {
            const data = req.body;
            console.log("Received Webhook Data:", JSON.stringify(data, null, 2));

            if (data.entry && data.entry[0].changes && data.entry[0].changes[0].value.messages) {
                const message = data.entry[0].changes[0].value.messages[0];
                const from = message.from;
                const messageType = message.type;

                console.log(`Processing message of type: ${messageType} from: ${from}`);
                let responseText = '';
                let fileInfo = null;

                switch (messageType) {
                    case 'text':
                        responseText = `Received your message: ${message.text.body}`;
                        break;

                    case 'audio':
                    case 'voice':
                        console.log('Audio message received:', message[messageType]);
                        fileInfo = await WhatsappWebhookController.downloadMedia(message[messageType], messageType);
                        responseText = `Audio received and saved as: ${fileInfo.filename}\nSize: ${(fileInfo.size / 1024).toFixed(2)}KB\nType: ${fileInfo.mimeType}`;
                        break;

                    case 'image':
                        console.log('Image message received:', message.image);
                        fileInfo = await WhatsappWebhookController.downloadMedia(message.image, messageType);
                        responseText = `Image received and saved as: ${fileInfo.filename}\nSize: ${(fileInfo.size / 1024).toFixed(2)}KB`;
                        if (message.image.caption) {
                            responseText += `\nCaption: ${message.image.caption}`;
                        }
                        break;

                    case 'video':
                        console.log('Video message received:', message.video);
                        fileInfo = await WhatsappWebhookController.downloadMedia(message.video, messageType);
                        responseText = `Video received and saved as: ${fileInfo.filename}\nSize: ${(fileInfo.size / 1024 / 1024).toFixed(2)}MB`;
                        if (message.video.caption) {
                            responseText += `\nCaption: ${message.video.caption}`;
                        }
                        break;

                    case 'document':
                        console.log('Document message received:', message.document);
                        fileInfo = await WhatsappWebhookController.downloadMedia(message.document, messageType);
                        responseText = `Document received and saved as: ${fileInfo.filename}\nSize: ${(fileInfo.size / 1024).toFixed(2)}KB\nType: ${fileInfo.mimeType}`;
                        break;

                    case 'sticker':
                        console.log('Sticker message received:', message.sticker);
                        fileInfo = await WhatsappWebhookController.downloadMedia(message.sticker, messageType);
                        responseText = `Sticker received and saved as: ${fileInfo.filename}`;
                        break;

                    case 'location':
                        console.log('Location message received:', message.location);
                        responseText = WhatsappWebhookController.formatLocation(message.location);
                        break;

                    case 'contacts':
                        console.log('Contacts message received:', message.contacts);
                        responseText = WhatsappWebhookController.formatContacts(message.contacts);
                        break;

                    case 'interactive':
                        console.log('Interactive message received:', message.interactive);
                        if (message.interactive.type === 'button_reply') {
                            responseText = `Button selected: ${message.interactive.button_reply.title}`;
                        } else if (message.interactive.type === 'list_reply') {
                            responseText = `List item selected: ${message.interactive.list_reply.title}`;
                        }
                        break;

                    default:
                        responseText = `Received message of type: ${messageType}`;
                }

                console.log('Sending response:', responseText);
                await WhatsAppActionsController.sendTextMessage(from, responseText);
            }

            res.sendStatus(200);
        } catch (error) {
            console.error('Error handling webhook:', error);
            res.sendStatus(500);
        }
    }
}

module.exports = WhatsappWebhookController; 