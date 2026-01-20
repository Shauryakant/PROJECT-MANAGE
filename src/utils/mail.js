import Mailgen from "mailgen";
import nodemailer from "nodemailer";
const sendEmail = async function (options) {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Mailgen",
      link: "https://taskmanagelink.com",
    },
  });
  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: Number(process.env.MAIL_PORT),
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASSWORD,
    },
  });
  console.log({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    user: process.env.MAIL_USER,
  });

  const emailHtml = mailGenerator.generate(options.mailgenContent);
  const emailText = mailGenerator.generatePlaintext(options.mailgenContent);
  try {
    await transporter.sendMail({
      from: "mail.taskmanager@example.com",
      to: options.email,
      subject: options.subject,
      text: emailText,
      html: emailHtml,
    });
  } catch (error) {
    console.error("check credentials mail not send");
    console.error("Error", error);
  }
};

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our App! we are ecited to welcome you",
      action: {
        instructions: "To verify your email please click here",
        button: {
          color: "#22BC66",
          text: "verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help , or have questions? reply to this email we would love to help",
    },
  };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset password",
      action: {
        instructions: "To reset your password click here",
        button: {
          color: "#22BC66",
          text: "Reset password",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help , or have questions? reply to this email we would love to help",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
};
