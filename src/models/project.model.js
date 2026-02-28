import mongoose, { Schema } from "mongoose";
const projectSchema=new Schema(
    {
        description:{
            type:String,
            required:true
        },
        name:{
            type:String,
            required:true
        },
        createdBy:{
            type:Schema.Types.ObjectId,
            ref:"User",
            required:true
        }
    },
    {
        timestamps:true
    }
)
export const Project=mongoose.model("Project",projectSchema);