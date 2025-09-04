import userModel from "../models/user.model.js";


export const blockInactiveUsers = async () => {
    try {
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        // const tenSecondsAgo = new Date(Date.now() - 10 * 1000);

        const result = await userModel.updateMany(
            {
                lastActivityAt: { $lt: sevenDaysAgo },
                accountVerified: true
            },
            {
                $set: { accountVerified: false }
            }
        );

        console.log(`Blocked ${result.modifiedCount} inactive users`);
    } catch (err) {
        console.error("Error blocking inactive users:", err);
    }
};
