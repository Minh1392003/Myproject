import mongoose from 'mongoose';
import Chapter, { chapterSchema } from '../Schema/Chapter.js';
import Blog from '../Schema/Blog.js';
import User from '../Schema/User.js';

export const registerModels = () => {
    if (!mongoose.models.chapters) {
        mongoose.model('chapters', chapterSchema);
    }
    if (!mongoose.models.blogs) {
        mongoose.model('blogs', Blog.schema);
    }
    if (!mongoose.models.users) {
        mongoose.model('users', User.schema);
    }
}; 