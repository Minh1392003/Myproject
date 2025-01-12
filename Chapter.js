import mongoose from "mongoose";

const bookmarkSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    bookmarkedAt: {
        type: Date,
        default: Date.now
    }
});

const chapterSchema = new mongoose.Schema({
    blog_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'blogs',
        required: true
    },
    chapter_id: {
        type: Number,
        required: true
    },
    title: {
        type: String,
        required: true
    },
    content: {
        type: mongoose.Schema.Types.Mixed,
        required: true
    },
    order: {
        type: Number,
        required: true
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    bookmarkedBy: [bookmarkSchema],
    publishedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Chapter = mongoose.model("chapters", chapterSchema);
export { chapterSchema };
export default Chapter;


