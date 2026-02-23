import mongoose, { Schema } from "mongoose";

const noteSchema=new Schema(
    {
        content:{
            type:String,
            required:true,
            trim:true
        },
        project:{
            type:Schema.Types.ObjectId,
            ref:"Project"
        },
        createdBy:{
            type:Schema.Types.ObjectId,
            ref:"User"
        }
    },{
        timestamps:true
    }
)
export const Note=mongoose.model("Note",noteSchema);