import userModel from "../models/user.model.js";
import redisClient from "../services/redis.service.js";

export const authenticateUsers = async (req, res, next) => {
    try {
        const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({ error: "Unauthorized User." });
        }

        const isTokenBlackListed = await redisClient.get(`blacklist:${token}`);

        if (isTokenBlackListed) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const decoded = await userModel.isVerifyToken(token);
        let user = await redisClient.get(`user:${decoded._id}`); // Key format adjust

        if (user) {
            user = JSON.parse(user);
        }

        if (!user) {
            user = await userModel.findById(decoded._id);
            if (user) {
                delete user._doc.password;
                redisClient.set(`user:${user._id}`, JSON.stringify(user), 'EX', 3600); // TTL set
            } else {
                return res.status(404).json({ error: "User not found in Database, please login again." });
            }
        }

        req.user = user;
        req.tokenData = { token, ...decoded }; // Store token data in request object

        next();
    } catch (error) {
        console.log("Authentication error:", error);
        return res.status(400).json({
            error: "Invalid token please login again or Refresh this page."
        });
    }
};








// import userModel from "../models/user.model.js";
// import redisClient from "../services/redis.service.js";


// export const authenticateUser = async (req, res, next) => {

//     try {
//         const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];

//         if (!token) {
//             return res.status(401).json({ error: "Unauthorized User." });
//         }

//         const isTokenBlackListed = await redisClient.get(`blacklist:${token}`);

//         if (isTokenBlackListed) {
//             return res.status(401).json({ message: 'Unauthorized' })
//         }


//         const decoded = await userModel.isVerifyToken(token);
//         let user = await redisClient.get(decoded._id);

//         if (user) {
//             user = JSON.parse(user);
//         }

//         if (!user) {
//             user = await userModel.findById(decoded._id);
//             if (user) {
//                 delete user._doc.password;
//                 redisClient.set(`user: ${user._id}`, JSON.stringify(user));
//             } else {
//                 return res.status(404).json({ error: "User not found in Database, please login again." });
//             }
//         }

//         req.user = user;
//         req.tokenData = { token, ...decoded }; // Store token data in request object

//         next();

//     } catch (error) {
//         console.log("Authentication error:", error);
//         return res.status(400).json({
//             error: "Invalid token please login again or Refresh this page."
//         });
//     }
// }

