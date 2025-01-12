import mongoose from "mongoose";

const CategorySchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 2
    },
    description: {
        type: String,
        trim: true,
        default: ''
    }
},
{
    timestamps: {
        createdAt: 'publishedAt',
        updatedAt: 'updatedAt'
    }
});

export default mongoose.model('Category', CategorySchema);