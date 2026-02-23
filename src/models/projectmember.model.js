import mongoose, { Schema } from "mongoose";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js"
const projectMemberSchema=new Schema(
    {
        user:{
            type:Schema.Types.ObjectId,
            ref:"User"
        },
        assignedToProject:{
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
export const ProjectMember=mongoose.model("ProjectMember",projectMemberSchema);