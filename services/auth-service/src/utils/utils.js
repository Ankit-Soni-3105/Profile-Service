
function generateEmailTemplate(verificationCode) {
    return `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 12px; background: linear-gradient(135deg, #b6e388 0%, #7ed957 100%); box-shadow: 0 4px 24px rgba(126,217,87,0.15); border: 1px solid #b6e388;">
      <div style="background: #4CAF50; border-radius: 12px 12px 0 0; padding: 24px 0; text-align: center;">
        <h1 style="margin: 0; color: #fff; font-size: 2.2em; letter-spacing: 2px; font-weight: bold; text-shadow: 0 2px 8px #7ed957;">Throne8</h1>
        <p style="margin: 8px 0 0 0; color: #e8f5e9; font-size: 1.1em; font-weight: 500;">Welcome to the Throne8 Experience</p>
      </div>
      <div style="padding: 32px 24px 24px 24px;">
        <h2 style="color: #388e3c; text-align: center; margin-bottom: 16px; font-size: 1.5em;">Your Verification Code</h2>
        <p style="font-size: 17px; color: #333; text-align: center; margin-bottom: 8px;">Dear User,</p>
        <p style="font-size: 16px; color: #333; text-align: center; margin-bottom: 24px;">Please use the code below to verify your email address:</p>
        <div style="text-align: center; margin: 24px 0;">
          <span style="display: inline-block; font-size: 32px; font-weight: bold; color: #fff; background: linear-gradient(90deg, #7ed957 0%, #4CAF50 100%); padding: 16px 40px; border-radius: 8px; box-shadow: 0 2px 8px #7ed957; letter-spacing: 2px; border: 2px solid #388e3c;">
            ${verificationCode}
          </span>
        </div>
        <p style="font-size: 16px; color: #333; text-align: center; margin-bottom: 8px;">This code will expire in <b>10 minutes</b>.</p>
        <p style="font-size: 15px; color: #333; text-align: center; margin-bottom: 24px;">If you did not request this, please ignore this email.</p>
      </div>
      <footer style="background: #e8f5e9; border-radius: 0 0 12px 12px; padding: 18px 0; text-align: center; font-size: 15px; color: #388e3c;">
        <p style="margin: 0;">Thank you,<br><span style="font-weight: bold; color: #4CAF50;">Throne8 Team</span></p>
        <p style="font-size: 12px; color: #7ed957; margin-top: 8px;">This is an automated message. Please do not reply to this email.</p>
      </footer>
    </div>
  `;
}

export { generateEmailTemplate };