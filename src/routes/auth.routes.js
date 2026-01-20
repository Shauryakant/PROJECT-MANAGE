import Router from "express";
import {
  login,
  registerUser,
  logout,
  resendverifyEmail,
  verifyEmail,
  refreshAccessToken,
  changePassword,
  resetForgotPassword,
  forgotPasswordRequest,
  getCurrentUser,
} from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userLoginValidator,
  userRegisterValidator,
  userResetForgotPasswordValidator,
} from "../middlewares/index.js";
import { checkToken } from "../middlewares/auth.middleware.js";
const router = Router();
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);

router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
router
  .route("/reset-password/:resetToken")
  .post(userResetForgotPasswordValidator(), validate, resetForgotPassword);
router
  .route("/change-password")
  .post(
    checkToken,
    userChangeCurrentPasswordValidator(),
    validate,
    changePassword,
  );
//insecure
router.route("/logout").post(checkToken, logout);
router.route("/verify-email/:verificationToken").post(verifyEmail);
router.route("/resend-email-verification").post(checkToken, resendverifyEmail);
router.route("/refresh-token").post(checkToken, refreshAccessToken);

router.route("/current-user").post(checkToken,getCurrentUser);

export default router;

// console.log(userRegisterValidator(), validate, registerUser);
