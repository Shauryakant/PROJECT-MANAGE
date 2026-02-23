import mongoose, { Schema } from "mongoose";

const subtaskSchema=new Schema(
    {
        details:{
            type:String,
            required:true,
            trim:true
        },
        task:{
            type:Schema.Types.ObjectId,
            ref:"Task"
        },
        completed:{
            type:Boolean,
            default:true
        },
    },{
        timestamps:true
    }
)
export const Subtask=mongoose.model("Subtask",subtaskSchema);