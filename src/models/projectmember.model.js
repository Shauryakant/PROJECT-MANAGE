import mongoose, { Schema } from "mongoose";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js"
const projectmemberSchema=new Schema(
    {
        user:{
            type:Schema.Types.ObjectId,
            ref:"User"
        },
        project:{
            type:Schema.Types.ObjectId,
            ref:"Project"
        },
        assignedBy:{
            type:Schema.Types.ObjectId,
            ref:"User"
        },
        role:{
            type:String,
            enum:AvailableUserRole,
            default:UserRolesEnum.MEMBER
        }
    },{
        timestamps:true
    }
)
export const Projectmember=mongoose.model("Projectmember",projectmemberSchema);