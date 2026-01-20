import {body} from "express-validator"
const userRegisterValidator =()=>{
    return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("should not be empty")
            .isEmail()
            .withMessage("It should be email"),
        body("username")
            .trim()
            .notEmpty()
            .withMessage("should not be empty")
            .isLowercase()
            .withMessage("should be lowercase")
            .isLength({min:3})
            .withMessage("length should be greater than 3"),
        body("password")
            .trim()
            .notEmpty()
            .withMessage("should not be empty")
            .isLowercase(),
        body("fullname")
            .optional()
            .trim()
    
    ]

}
const userLoginValidator=() =>{
    return [
        body("email")
        .isEmail()
        .withMessage("Email is invalid"),
        body("password")
        .notEmpty()
        .withMessage("Password is required")
    ]
};
const userChangeCurrentPasswordValidator=()=>{
    return [
        body("oldPassword").notEmpty().withMessage("Old password is required"),
        body("newPassword").notEmpty().withMessage("New password is required")
    ]
}
const userForgotPasswordValidator=()=>{
    return [
        body("email")
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("email is invalid")
    ]
}
const userResetForgotPasswordValidator=()=>{
    return [
        body("newPassword")
            .notEmpty()
            .withMessage("Password is required")
    ]
}


export {userForgotPasswordValidator,userResetForgotPasswordValidator,userChangeCurrentPasswordValidator,userLoginValidator,userRegisterValidator}