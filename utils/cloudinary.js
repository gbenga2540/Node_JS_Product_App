require('dotenv').config();
const cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: process.env.NODE_CLOUDINARY_NAME,
    api_key: process.env.NODE_CLOUDINARY_API_KEY,
    api_secret: process.env.NODE_CLOUDINARY_API_SECRET,
});

module.exports = { cloudinary };