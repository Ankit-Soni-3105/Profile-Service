import contactModel from "../models/contactinforamtion.model.js";


export const createContact = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { primaryEmail, secondaryEmail, phoneNumber, website } = req.body;

        const contactInfo = new contactModel({ 
            userId, 
            primaryEmail, 
            secondaryEmail, 
            phoneNumber, 
            website 
        });
        const savedContact = await contactInfo.save();

        const cacheKey = `contact:${userId}`;
        await setCache(cacheKey, savedContact, 3600);
        res.status(201).json({
            message: 'Contact information created successfully',
            data: savedContact
        });
    } catch (error) {
        console.error('Error creating contact info:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export default { createContact };