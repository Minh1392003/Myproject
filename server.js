import express, { response } from 'express';
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt, { decode } from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';
import serviceAccountKey from '../server/final-project-9968b-firebase-adminsdk-fr1kx-32af45a1ef.json' assert { type: 'json' };
import { getAuth } from 'firebase-admin/auth';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import Stripe from 'stripe';
import PDFDocument from 'pdfkit';
import fs from 'fs';
import axios from 'axios';
import nodemailer from 'nodemailer';

import User from './Schema/User.js';
import User1 from './Schema/user1.js';
import Blog from './Schema/Blog.js';
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';
import Category from './Schema/Category.js';
import { registerModels } from './models/index.js';
import Chapter, { chapterSchema } from './Schema/Chapter.js';



const server = express();
const PORT = 3000;
const { verify } = jwt;
const stripe = new Stripe(process.env.SECRET_STRIPE_KEY);



admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors({ origin: 'http://localhost:5173' }));

mongoose.connect(process.env.DB_LOCATION, { autoIndex: true })
    .then(() => {
        console.log('MongoDB connected successfully');
        registerModels();
    })
    .catch((err) => console.error('MongoDB connection error:', err));

cloudinary.config({
    cloud_name: 'drnfgt3u1',
    api_key: process.env.CLOUDINARY_APIKEY,
    api_secret: process.env.CLOUDINARY_APISECRET,
});

server.post("/upload-image", upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ "error": "No file uploaded" });
    }

    try {
        const result = await cloudinary.uploader.upload_stream(
            { resource_type: 'image' },
            (error, result) => {
                if (error) {
                    return res.status(500).json({ "error": "Image upload failed" });
                }
                return res.status(200).json({ url: result.secure_url });
            }
        ).end(req.file.buffer);
    } catch (error) {
        return res.status(500).json({ "error": "Image upload failed" });
    }
});


const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    if (token == null) {
        return res.status(401).json({ error: "No access token" });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Access token is invalid" });
        }

        req.user = user.id;
        req.admin = user.admin
        req.premium = user.premium
        next();
    });
};

server.post("/updated-profile-img", verifyJWT, (req, res) => {
    let { url } = req.body;

    User.findByIdAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
        .then(() => {
            return res.status(200).json({ profile_img: url })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

const formatDatatoSend = (user) => {
    const access_token = jwt.sign({ id: user._id, admin: user.admin, premium: user.premium }, process.env.SECRET_ACCESS_KEY);

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
        isAdmin: user.admin,
        isPremium: user.premium
    };
};


const generateUsername = async (email) => {
    let username = email.split('@')[0];
    let isUsernameNotUnique = await User.exists({ "personal_info.username": username });
    if (isUsernameNotUnique) {
        username += nanoid().substring(0, 5);
    }
    return username;
};

server.post("/signup", async (req, res) => {
    const { fullname, email, password } = req.body;

    if (!fullname || fullname.trim().length < 3) {
        return res.status(403).json({ "error": "Fullname must be at least 3 characters" });
    }

    if (!email || !email.length) {
        return res.status(403).json({ "error": "Enter Email" });
    }

    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email is invalid" });
    }

    if (!password || !passwordRegex.test(password)) {
        return res.status(403).json({
            "error": "Password must be between 6 and 20 characters long, with at least one numeric digit, one lowercase, and one uppercase letters"
        });
    }

    const hashed_password = await bcrypt.hash(password, 10);
    let username = await generateUsername(email);

    let user = new User({
        personal_info: { fullname, email, password: hashed_password, username }
    });

    try {
        const savedUser = await user.save();
        return res.status(200).json(formatDatatoSend(savedUser));
    } catch (err) {
        if (err.code === 11000) {
            return res.status(500).json({ "error": "Email already exists" });
        }
        return res.status(500).json({ "error": err.message });
    }
});

server.post("/signin", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ "personal_info.email": email });
        if (!user) {
            return res.status(403).json({ "error": "Email not found" });
        }

        if (!user.google_auth) {
            const result = await bcrypt.compare(password, user.personal_info.password);
            if (!result) {
                return res.status(403).json({ "error": "Incorrect password" });
            }
            return res.status(200).json(formatDatatoSend(user));
        } else {
            return res.status(403).json({ "error": "Account was created using Google. Try logging in with Google." });
        }
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ "error": err.message });
    }
});

server.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        
        const user = await User.findOne({ "personal_info.email": email });
        if (!user) {
            return res.status(404).json({ error: "No account found with this email" });
        }

        const token = jwt.sign(
            { 
                id: user._id,
                email: user.personal_info.email,
                random: Math.random().toString(36).substring(7) + Date.now().toString(36)
            },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "1h" }
        );

        // Save token to user model
        await User.findByIdAndUpdate(user._id, {
            resetPasswordToken: token,
            resetPasswordExpires: Date.now() + 3600000 // 1 hour
        });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        const resetLink = `${process.env.CLIENT_URL}/reset-password?email=${email}&token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Reset your password',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Reset Your Password</h2>
                    <p>Hello ${user.personal_info.fullname},</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" 
                           style="background-color: #007bff; color: white; padding: 12px 24px; 
                                  text-decoration: none; border-radius: 4px; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                    <hr style="border: 1px solid #eee; margin: 20px 0;" />
                    <p style="color: #666; font-size: 12px;">
                        This is an automated email, please do not reply.
                    </p>
                </div>
            `
        };

        await new Promise((resolve, reject) => {
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(info);
                }
            });
        });

        return res.status(200).json({ 
            status: 'success',
            message: 'Password reset link has been sent to your email' 
        });

    } catch (error) {
        console.error("Error in forgot-password:", error);
        return res.status(500).json({ 
            error: error.message || "Failed to send reset email"
        });
    }
});

server.post('/reset-password', async (req, res) => {
    try {
        const { email, token, password } = req.body;

        if (!password || !passwordRegex.test(password)) {
            return res.status(400).json({ 
                error: "Password must be between 6 and 20 characters long, with at least one numeric digit, one lowercase, and one uppercase letter" 
            });
        }

        const user = await User.findOne({ 
            "personal_info.email": email,
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(401).json({ error: "Invalid or expired password reset token" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Update password and clear reset token
        await User.findByIdAndUpdate(user._id, { 
            "personal_info.password": hashedPassword,
            resetPasswordToken: null,
            resetPasswordExpires: null
        });

        return res.status(200).json({ 
            status: "success",
            message: "Password has been reset successfully" 
        });
    } catch (error) {
        console.error("Reset password error:", error);
        return res.status(500).json({ error: "Failed to reset password" });
    }
});


server.post("/google-auth", async (req, res) => {
    const { access_token } = req.body;

    try {
        const decodedUser = await getAuth().verifyIdToken(access_token);
        const { email, name, picture } = decodedUser;
        const pictureUrl = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ "personal_info.email": email })
            .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth");

        if (user) {
            if (!user.google_auth) {
                return res.status(403).json({ "error": "This email was signed up with Google. Please log in again with password." });
            }
        } else {
            const username = await generateUsername(email);

            user = new User({
                personal_info: { fullname: name, email, username, profile_img: pictureUrl },
                google_auth: true
            });

            await user.save();
        }

        return res.status(200).json(formatDatatoSend(user));
    } catch (err) {
        return res.status(500).json({ "error": "Failed to authenticate with Google. Try with another account." });
    }
});

server.post("/change-password", verifyJWT, (req, res) => {
    let { currentPassword, newPassword } = req.body;

    if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: "Password must be between 6 and 20 characters long, with at least one numeric digit, one lowercase, and one uppercase letters" })
    }

    User.findOne({ _id: req.user })
        .then((user) => {
            if (user.google_auth) {
                return res.status(403).json({ error: "You can't change account's password because you logged in through google" })
            }

            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Some error occured while changing the password, please try again later" })
                }

                if (!result) {
                    return res.status(403).json({ error: "Incorrect current password" })
                }

                bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
                        .then((u) => {
                            return res.status(200).json({ status: 'Password changed' })
                        })
                        .catch((err) => {
                            return res.status(500).json({ error: 'Some error occured while saving new password, lease try again later' })
                        })
                })
            })
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ error: "User not found" })
        })
})

server.post('/latest-stories', (req, res) => {
    let { page } = req.body;
    let maxLimit = 24;

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt isPremium -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/all-latest-stories-count", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message)
            return res.status(500).json({ error: err.message })
        })
})

server.get("/trending-stories", (req, res) => {
    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({
            "activity.total_reads": -1,
            "activity.total_likes": -1,
            "publishedAt": -1
        })
        .select("blog_id title des banner activity tags publishedAt isPremium -_id")
        .limit(6)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/search-stories", (req, res) => {
    let { tag, query, author, page, limit, eliminate_blog } = req.body;

    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { author, draft: false }
    }

    let maxLimit = limit ? limit : 24;

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt isPremium -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/search-stories-count", (req, res) => {
    let { tag, query, author } = req.body;

    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

server.post("/search-users", (req, res) => {
    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
        .limit(50)
        .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .then(users => {
            return res.status(200).json({ users })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/get-profile", (req, res) => {
    let { username } = req.body;

    User.findOne({ "personal_info.username": username })
        .select("-personal_info.password -google_auth -updateAt -blogs")
        .then(user => {
            return res.status(200).json(user)
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: err.message });
        })
})

server.post("/update-profile", verifyJWT, (req, res) => {
    let { username, bio, social_links } = req.body;

    let bioLimit = 150;

    if (username.length < 3) {
        return res.status(403).json({ error: "Username should be at least 3 letters long" })
    }
    if (bio.length > bioLimit) {
        return res.status(403).json({ error: `Bio should not be more than ${bioLimit} characters` })
    }

    let socialLinkArr = Object.keys(social_links);

    try {
        for (let i = 0; i < socialLinkArr.length; i++) {
            if (social_links[socialLinkArr[i]].length) {
                let hostname = new URL(social_links[socialLinkArr[i]]).hostname;

                if (!hostname.includes(`${socialLinkArr[i]}.com`) && socialLinkArr[i] != 'website') {
                    return response.status(403).json({ error: `${socialLinkArr[i]} link is invalid. You must enter a full link` })
                }
            }
        }
    } catch (err) {
        return res.status(500).json({ error: "You must provide full social links with http(s) included" })
    }

    let updateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links
    }

    User.findByIdAndUpdate({ _id: req.user }, updateObj, {
        runValidators: true
    })
        .then(() => {
            return res.status(200).json({ username })
        })
        .catch(err => {
            if (err.code === 11000) {
                return res.status(409).json({ error: "Username is already taken" })
            }
            return res.status(500).json({ error: err.message })
        })
})

server.post('/create-story', verifyJWT, (req, res) => {
    let authorId = req.user;
    let isAdmin = req.admin;

    if (isAdmin) {
        let { title, des, banner, tags, content, draft, id, isPremium } = req.body;

        if (!title || !title.length) {
            return res.status(403).json({ error: "You must provide a title to publish the story" });
        }

        if (!draft) {
            if (!des || des.length > 200) {
                return res.status(403).json({ error: "You must provide a story description under 200 characters" });
            }

            if (!banner || !banner.length) {
                return res.status(403).json({ error: "You must provide a story banner to publish" });
            }

            if (!content.blocks || content.blocks.length === 0) {
                return res.status(403).json({ error: "There must be some story content to publish it" });
            }

            if (!tags || tags.length === 0 || tags.length > 10) {
                return res.status(403).json({ error: "Provide tags in order to publish the story, Maximum 10" });
            }
        }

        tags = tags.map(tag => tag.toLowerCase());
        let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();

        if (id) {
            Blog.findOneAndUpdate(
                { blog_id },
                {
                    title,
                    des,
                    banner,
                    content,
                    tags,
                    draft: draft ? draft : false,
                    isPremium: isPremium || false
                }
            )
                .then(blog => {
                    return res.status(200).json({ id: blog_id });
                })
                .catch(err => {
                    return res.status(500).json({ error: "Failed to update total posts number" })
                })
        } else {
            let blog = new Blog({
                title,
                des,
                banner,
                content,
                tags,
                author: authorId,
                blog_id,
                draft: Boolean(draft),
                isPremium: Boolean(isPremium)
            });

            blog.save()
                .then(blog => {
                    let incrementVal = draft ? 0 : 1;

                    User.findOneAndUpdate(
                        { _id: authorId },
                        {
                            $inc: { "account_info.total_posts": incrementVal },
                            $push: { "blogs": blog._id }
                        }
                    )
                        .then(user => {
                            return res.status(200).json({ id: blog.blog_id })
                        })
                        .catch(err => {
                            return res.status(500).json({ error: "Failed to update total posts number" })
                        })
                })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })
        }
    } else {
        return res.status(500).json({ error: "You don't have permission to create any stories" })
    }
})



server.post("/get-story", async (req, res) => {
    try {
        const { blog_id } = req.body;
        
        if (!blog_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        const ChapterModel = mongoose.models.chapters || mongoose.model('chapters', Chapter.schema);

        const blog = await Blog.findOne({ blog_id })
            .populate("author", "personal_info")
            .populate({
                path: "chapters",
                model: ChapterModel
            });

        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        res.status(200).json({ blog });
    } catch (error) {
        console.error("Error fetching story:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

server.post("/like-story", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { _id, islikedByUser } = req.body;

    let incrementVal = !islikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {
            if (!islikedByUser) {
                let like = new Notification({
                    type: "like",
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id
                })

                like.save().then(notification => {
                    return res.status(200).json({ liked_by_user: true })
                })
            } else {

                Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
                    .then(data => {
                        return res.status(200).json({ liked_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })

            }
        })
})

server.post("/isliked-by-user", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { _id } = req.body;

    Notification.exists({ user: user_id, type: "like", blog: _id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/add-comment", verifyJWT, (req, res) => {
    let user_id = req.user;
    let premium = req.premium;

    let { _id, blog_author, comment, replying_to, notification_id } = req.body;

    if (!comment.length) {
        return res.status(403).json({ error: 'Write something to leave a comment' });
    }

    let commentObj = {
        blog_id: _id, 
        blog_author, 
        comment, 
        commented_by: user_id,
    }

    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true;
    }

    new Comment(commentObj).save().then(async commentFile => {
        let { comment, commentedAt, children } = commentFile;

        const populatedComment = await Comment.findById(commentFile._id)
            .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img premium");

        Blog.findOneAndUpdate(
            { _id }, 
            { 
                $push: { "comments": commentFile._id }, 
                $inc: { 
                    "activity.total_comments": 1, 
                    "activity.total_parent_comments": replying_to ? 0 : 1 
                }
            }
        ).then(blog => { console.log('New comment created') });

        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id
        }

        if (replying_to) {
            notificationObj.replied_on_comment = replying_to;

            await Comment.findOneAndUpdate(
                { _id: replying_to }, 
                { $push: { children: commentFile._id } }
            ).then(replyingToCommentDoc => { 
                notificationObj.notification_for = replyingToCommentDoc.commented_by 
            });

            if (notification_id) {
                Notification.findOneAndUpdate(
                    { _id: notification_id }, 
                    { reply: commentFile._id }
                ).then(notification => console.log('notification updated'));
            }
        }

        new Notification(notificationObj).save()
            .then(notification => console.log('New notification created'));

        return res.status(200).json({
            ...populatedComment.toObject(),
            _id: commentFile._id,
            comment,
            commentedAt,
            children
        });
    });
})

server.post("/get-story-comments", (req, res) => {
    let { blog_id, skip } = req.body;

    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img premium")
        .skip(skip)
        .limit(maxLimit)
        .sort({
            'commentedAt': -1
        })
        .then(comment => {
            console.log(comment, blog_id, skip)
            return res.status(200).json(comment);
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})

server.post("/add-chapter", verifyJWT, async (req, res) => {
    const user_id = req.user;

    const { title, content, blog_id, order } = req.body;

    try {
        const blog = await Blog.findOne({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        if (blog.author.toString() !== user_id) {
            return res.status(403).json({ error: "You are not authorized to add chapters to this blog" });
        }

        if (!title || !content || !blog_id || order === undefined) {
            return res.status(400).json({ error: "All fields are required." });
        }

        const generateChapterId = async () => {
            const lastChapter = await Chapter.findOne().sort({ chapter_id: -1 }).exec();
            return lastChapter && typeof lastChapter.chapter_id === 'number' ? lastChapter.chapter_id + 1 : 1;
        };

        const chapterObj = {
            title,
            content,
            blog_id: blog._id,
            order,
            author: user_id,
            chapter_id: await generateChapterId(),
        };

        if (isNaN(chapterObj.chapter_id)) {
            throw new Error("Invalid chapter_id generated");
        }

        const newChapter = await new Chapter(chapterObj).save();

        await Blog.findByIdAndUpdate(
            blog._id,
            {
                $push: { chapters: newChapter._id },
                $inc: { "activity.total_chapters": 1 }
            }
        );

        return res.status(201).json({
            message: "Chapter created successfully",
            chapter: newChapter,
        });
    } catch (error) {
        console.error("Error creating chapter:", error);
        return res.status(500).json({ error: error.message || "Server error" });
    }
});

server.post("/get-chapters", async (req, res) => {
    try {
        const { blog_id, chapter_id } = req.body;
        let userId = null;

        // Kiểm tra authentication token nếu có
        const authHeader = req.headers['authorization'];
        if (authHeader) {
            const token = authHeader.split(" ")[1];
            try {
                const decoded = jwt.verify(token, process.env.SECRET_ACCESS_KEY);
                userId = decoded.id;
            } catch (err) {
                console.log("Invalid token");
            }
        }

        const blog = await Blog.findOne({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        const chapters = await Chapter.find({ blog_id: blog._id })
            .select('title order publishedAt')
            .sort({ order: 1 });

        let selectedChapter = null;
        if (chapter_id) {
            selectedChapter = await Chapter.findOne({ _id: chapter_id, blog_id: blog._id })
                .populate('author', 'personal_info.fullname personal_info.username personal_info.profile_img');

            if (!selectedChapter) {
                return res.status(404).json({ error: "Chapter not found" });
            }

            // Kiểm tra bookmark status nếu có userId
            if (userId) {
                const isBookmarked = selectedChapter.bookmarkedBy.some(
                    bookmark => bookmark.user.toString() === userId
                );
                selectedChapter = selectedChapter.toObject();
                selectedChapter.isBookmarked = isBookmarked;
            }
        }

        return res.status(200).json({
            chapters,
            selectedChapter,
            blog_title: blog.title,
            total_chapters: blog.activity.total_chapters
        });
    } catch (error) {
        console.error("Error fetching chapters:", error);
        return res.status(500).json({ error: "Server error" });
    }
});

server.post("/get-replies", (req, res) => {
    let { _id, skip } = req.body;

    let maxLimit = 5;

    Comment.findOne({ _id })
        .populate({
            path: "children",
            options: {
                limit: maxLimit,
                skip: skip,
                sort: { 'commentedAt': -1 }
            },
            populate: {
                path: 'commented_by',
                select: "personal_info.profile_img personal_info.fullname personal_info.username premium"
            },
            select: "-blog_id -updatedAt"
        })
        .select("children")
        .then(doc => {
            return res.status(200).json({ replies: doc.children })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

const deleteComments = (_id) => {
    Comment.findOneAndDelete({ _id })
        .then(comment => {
            if (comment.parent) {
                Comment.findByIdAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
                    .then(data => console.log('comment delte from parent'))
                    .catch(err => console.log(err));
            }

            Notification.findOneAndDelete({ comment: _id }).then(notification => console.log('comment notification deleted'))

            Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(notification => console.log('reply notification deleted'))

            Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
                .then(blog => {
                    if (comment.children.length) {
                        comment.children.map(replies => {
                            deleteComments(replies)
                        })
                    }
                })
        })
        .catch(err => {
            console.log(err.message);
        })
}

server.post("/delete-comment", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { _id } = req.body;

    Comment.findOne({ _id })
        .then(comment => {
            if (user_id == comment.commented_by || user_id == comment.blog_author) {
                deleteComments(_id);

                return res.status(200).json({ status: 'done' });
            } else {
                return res.status(403).json({ error: "You can not delete this comment" })
            }
        })
})

server.get("/new-notification", verifyJWT, (req, res) => {
    const user_id = req.user;

    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
        .then(result => {
            return res.status(200).json({ new_notification_available: !!result });
        })
        .catch(err => {
            console.error(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/notifications", verifyJWT, (req, res) => {
    const user_id = req.user;

    const { page = 1, filter = 'all', deletedDocCount = 0 } = req.body;
    const maxLimit = 10;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };
    let skipDocs = (page - 1) * maxLimit - deletedDocCount;

    if (filter !== 'all') {
        findQuery.type = filter;
    }

    Notification.find(findQuery)
        .skip(skipDocs)
        .limit(maxLimit)
        .populate("blog", "title blog_id")
        .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
        .populate("comment", "comment")
        .populate("replied_on_comment", "comment")
        .populate("reply", "comment")
        .sort({ createdAt: -1 })
        .select("createdAt type seen reply")
        .then(notifications => {

            Notification.updateMany(findQuery, { seen: true })
                .skip(skipDocs)
                .limit(maxLimit)
                .then(() => console.log('notification seen'))

            return res.status(200).json({ notifications });
        })
        .catch(err => {
            console.error(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/all-notifications-count", verifyJWT, (req, res) => {
    const user_id = req.user;
    const { filter = 'all' } = req.body;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };

    if (filter !== 'all') {
        findQuery.type = filter;
    }

    Notification.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ total: count });
        })
        .catch(err => {
            console.error(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/user-written-stories", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { page, draft, query, deletedDocCount } = req.body;

    let maxLimit = 5;

    let skipDocs = (page - 1) * maxLimit;

    if (deletedDocCount) {
        skipDocs -= deletedDocCount;
    }

    Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') })
        .skip(skipDocs)
        .limit(maxLimit)
        .sort({ publishedAt: -1 })
        .select(" title banner publishedAt blog_id activity des draft -_id")
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/user-written-stories-count", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { draft, query } = req.body;

    Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})

server.post("/delete-story", verifyJWT, async (req, res) => {
    let user_id = req.user;
    let isAdmin = req.admin;
    let { blog_id } = req.body;

    try {
        const blog = await Blog.findOne({ blog_id });
        
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        // Check if user is admin or the author of the blog
        if (!isAdmin && blog.author.toString() !== user_id) {
            return res.status(403).json({ error: "Not authorized to delete this blog" });
        }

        // Delete the blog
        await Blog.findOneAndDelete({ blog_id });
        
        // Delete related data
        await Promise.all([
            Notification.deleteMany({ blog: blog._id }),
            Comment.deleteMany({ blog_id: blog._id }),
            Chapter.deleteMany({ blog_id: blog._id }),
            User.findOneAndUpdate(
                { _id: blog.author },
                { 
                    $pull: { blogs: blog._id },
                    $inc: { "account_info.total_posts": -1 }
                }
            )
        ]);

        return res.status(200).json({ status: 'Blog deleted successfully' });
    } catch (err) {
        console.error("Error deleting blog:", err);
        return res.status(500).json({ error: err.message });
    }
})

server.post("/edit-chapter", verifyJWT, async (req, res) => {
    const user_id = req.user;
    const { title, content, blog_id, chapter_id, order } = req.body;

    try {
        const blog = await Blog.findOne({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        if (blog.author.toString() !== user_id) {
            return res.status(403).json({ error: "You are not authorized to edit this chapter" });
        }

        const updatedChapter = await Chapter.findByIdAndUpdate(
            chapter_id,
            { title, content, order },
            { new: true }
        );

        if (!updatedChapter) {
            return res.status(404).json({ error: "Chapter not found" });
        }

        return res.status(200).json({
            message: "Chapter updated successfully",
            chapter: updatedChapter,
        });
    } catch (error) {
        console.error("Error updating chapter:", error);
        return res.status(500).json({ error: error.message || "Server error" });
    }
});

server.post("/delete-chapter", verifyJWT, async (req, res) => {
    const user_id = req.user;
    const { chapter_id, blog_id } = req.body;

    try {
        const blog = await Blog.findOne({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        if (blog.author.toString() !== user_id) {
            return res.status(403).json({ error: "You are not authorized to delete this chapter" });
        }

        const deletedChapter = await Chapter.findByIdAndDelete(chapter_id);
        if (!deletedChapter) {
            return res.status(404).json({ error: "Chapter not found" });
        }

        await Blog.findByIdAndUpdate(blog._id, {
            $pull: { chapters: chapter_id },
            $inc: { "activity.total_chapters": -1 }
        });

        return res.status(200).json({
            message: "Chapter deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting chapter:", error);
        return res.status(500).json({ error: error.message || "Server error" });
    }
});

server.post("/create-category", verifyJWT, async (req, res) => {
    try {
        const { name, description } = req.body;

        if (!name) {
            return res.status(400).json({ error: "Category name is required" });
        }

        if (name.length < 2) {
            return res.status(400).json({ error: "Category name must be at least 2 characters long" });
        }

        const normalizedName = name.toLowerCase().trim();

        const existingCategory = await Category.findOne({ name: normalizedName });
        if (existingCategory) {
            return res.status(400).json({ error: "Category already exists" });
        }

        const category = new Category({
            name: normalizedName,
            description: description?.trim() || ''
        });

        const savedCategory = await category.save();

        return res.status(201).json({
            message: "Category created successfully",
            category: savedCategory
        });
    } catch (error) {
        console.error('Server error:', error);
        return res.status(500).json({
            error: "Failed to create category",
            details: error.message
        });
    }
});

server.get("/get-categories", async (req, res) => {
    try {
        const categories = await Category.find()
            .sort({ publishedAt: -1 })
            .select("name description publishedAt");
        return res.status(200).json(categories);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

server.put("/edit-category/:id", verifyJWT, async (req, res) => {
    try {
        const { name, description } = req.body;
        const categoryId = req.params.id;

        if (!name) {
            return res.status(400).json({ error: "Category name is required" });
        }

        if (name.length < 2) {
            return res.status(400).json({ error: "Category name must be at least 2 characters long" });
        }

        const normalizedName = name.toLowerCase().trim();

        const existingCategory = await Category.findOne({
            name: normalizedName,
            _id: { $ne: categoryId }
        });

        if (existingCategory) {
            return res.status(400).json({ error: "Category name already exists" });
        }

        const updatedCategory = await Category.findByIdAndUpdate(
            categoryId,
            {
                name: normalizedName,
                description: description?.trim() || ''
            },
            { new: true }
        );

        if (!updatedCategory) {
            return res.status(404).json({ error: "Category not found" });
        }

        return res.status(200).json({
            message: "Category updated successfully",
            category: updatedCategory
        });
    } catch (error) {
        console.error('Server error:', error);
        return res.status(500).json({ error: "Failed to update category" });
    }
});

server.delete("/delete-category/:id", verifyJWT, async (req, res) => {
    try {
        const categoryId = req.params.id;
        const deletedCategory = await Category.findByIdAndDelete(categoryId);

        if (!deletedCategory) {
            return res.status(404).json({ error: "Category not found" });
        }

        return res.status(200).json({
            message: "Category deleted successfully"
        });
    } catch (error) {
        console.error('Server error:', error);
        return res.status(500).json({ error: "Failed to delete category" });
    }
});

server.get("/admin/users", verifyJWT, async (req, res) => {
    try {
        const users = await User.find()
            .select("personal_info.fullname personal_info.username personal_info.email personal_info.profile_img account_info admin google_auth premium premiumStartDate premiumEndDate createdAt")
            .sort({ createdAt: -1 });

        return res.status(200).json(users);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

server.post("/admin/create-account", verifyJWT, async (req, res) => {
    try {
        console.log('Received request body:', req.body);
        const { fullname, email, password, isAdmin } = req.body;

        if (!fullname || fullname.trim().length < 3) {
            return res.status(403).json({ "error": "Fullname must be at least 3 characters" });
        }

        if (!email || !emailRegex.test(email)) {
            return res.status(403).json({ "error": "Invalid email address" });
        }

        if (!password || !passwordRegex.test(password)) {
            return res.status(403).json({ "error": "Password must be between 6 and 20 characters long, with at least one numeric digit, one lowercase, and one uppercase letters" });
        }

        // Check if email already exists
        const existingUser = await User.findOne({ "personal_info.email": email });
        if (existingUser) {
            return res.status(403).json({ "error": "Email already exists" });
        }

        // Hash password
        const hashed_password = await bcrypt.hash(password, 10);
        const username = await generateUsername(email);

        // Create new user
        const user = new User({
            personal_info: {
                fullname,
                email,
                password: hashed_password,
                username
            },
            admin: isAdmin
        });

        await user.save();
        console.log('User created successfully:', user);

        return res.status(200).json({ message: "Account created successfully" });
    } catch (error) {
        console.error("Error creating account:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.put("/admin/update-account/:id", verifyJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { fullname, username, isAdmin, isPremium } = req.body;

        if (!fullname || fullname.trim().length < 3) {
            return res.status(403).json({ "error": "Fullname must be at least 3 characters" });
        }

        if (!username || username.trim().length < 3) {
            return res.status(403).json({ "error": "Username must be at least 3 characters" });
        }

        const existingUser = await User.findOne({
            "personal_info.username": username,
            _id: { $ne: id }
        });

        if (existingUser) {
            return res.status(403).json({ "error": "Username already exists" });
        }

        const updatedUser = await User.findByIdAndUpdate(
            id,
            {
                "personal_info.fullname": fullname,
                "personal_info.username": username,
                admin: isAdmin,
                premium: isPremium
            },
            { new: true }
        ).select("personal_info.fullname personal_info.username personal_info.email personal_info.profile_img account_info admin premium google_auth");

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "Account updated successfully",
            user: updatedUser
        });
    } catch (error) {
        console.error("Error updating account:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.delete("/admin/delete-account/:id", verifyJWT, async (req, res) => {
    try {
        const { id } = req.params;


        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        await Blog.deleteMany({ author: id });

        await Comment.deleteMany({ commented_by: id });

        await Notification.deleteMany({
            $or: [
                { notification_for: id },
                { user: id }
            ]
        });

        await User.findByIdAndDelete(id);

        return res.status(200).json({
            message: "Account and all related data deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting account:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.post("/checkout", async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            mode: "payment",
            line_items: req.body.items.map(item => {
                return {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: item.name
                        },
                        unit_amount: Math.round(item.price * 100),
                    },
                    quantity: item.quantity
                }
            }),
            success_url: "http://localhost:5173/success",
            cancel_url: "http://localhost:5173/cancel"
        })
        res.json({ url: session.url })
    } catch (error) {
        console.error("Stripe error:", error);
        res.status(500).json({ error: error.message })
    }
})

server.post("/update-premium-status", verifyJWT, async (req, res) => {
    try {
        // Cập nhật trạng thái premium cho user
        const user = await User.findByIdAndUpdate(
            req.user,
            { 
                premium: true,
                premiumStartDate: new Date(),
                premiumEndDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
            },
            { new: true }
        ).select("personal_info.username personal_info.fullname personal_info.profile_img admin premium premiumStartDate premiumEndDate");

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const userData = formatDatatoSend(user);

        const notification = new Notification({
            type: "premium_upgrade",
            notification_for: user._id,
            message: "Your account has been upgraded to premium"
        });
        await notification.save();

        return res.status(200).json({
            success: true,
            user: userData
        });
    } catch (error) {
        console.error("Error updating premium status:", error);
        return res.status(500).json({ error: "Failed to update premium status" });
    }
});

const verifyPremium = (req, res, next) => {
    if (!req.premium) {
        return res.status(403).json({ error: "This feature requires a premium account" });
    }
    next();
};

server.post("/create-premium-story", verifyJWT, verifyPremium, (req, res) => {
    
});

server.get("/premium-stories", async (req, res) => {
    try {
        const premiumBlogs = await Blog.find({
            draft: false,
            isPremium: true
        })
            .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
            .sort({
                "publishedAt": -1
            })
            .select("blog_id title des banner activity tags publishedAt isPremium -_id")
            .limit(8);

        return res.status(200).json({ blogs: premiumBlogs });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

server.get("/download-story/:blog_id", verifyJWT, verifyPremium, async (req, res) => {
    try {
        const { blog_id } = req.params;

        // Đảm bảo model Chapter ��ược đăng ký
        const ChapterModel = mongoose.models.chapters || mongoose.model('chapters', chapterSchema);

        const blog = await Blog.findOne({ blog_id })
            .populate("author", "personal_info")
            .populate({
                path: "chapters",
                model: ChapterModel,  // Sử dụng ChapterModel đã đăng ký
                options: { sort: { 'order': 1 } },
                select: 'title content order'
            });

        if (!blog) {
            return res.status(404).json({ error: "Story not found" });
        }

        if (!blog.chapters || blog.chapters.length === 0) {
            return res.status(400).json({ error: "No chapters available for download" });
        }

        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: 50, bottom: 50, left: 50, right: 50 },
            bufferPages: true
        });

        const filename = `${blog.title.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${filename}`);

        doc.pipe(res);

        doc.fontSize(30)
            .font('Helvetica-Bold')
            .text(blog.title, { align: 'center' });

        doc.moveDown(2);

        doc.fontSize(16)
            .font('Helvetica')
            .text(`By ${blog.author.personal_info.fullname}`, { align: 'center' });

        doc.moveDown(4);

        if (blog.banner) {
            try {
                const response = await axios.get(blog.banner, { responseType: 'arraybuffer' });
                const imageBuffer = Buffer.from(response.data);
                doc.image(imageBuffer, {
                    fit: [400, 400],
                    align: 'center'
                });
            } catch (error) {
                console.error("Error loading banner image:", error);
            }
        }

        doc.moveDown(2);

        if (blog.des) {
            doc.fontSize(12)
                .font('Helvetica-Oblique')
                .text(blog.des, {
                    align: 'justify',
                    indent: 20,
                    columns: 1
                });
        }

        doc.addPage()
            .fontSize(24)
            .font('Helvetica-Bold')
            .text('Table of Contents', { align: 'center' });

        doc.moveDown(2);
        let pageNumbers = [];
        let currentPage = 3;

        blog.chapters.forEach((chapter, index) => {
            doc.fontSize(12)
                .font('Helvetica')
                .text(
                    `Chapter ${index + 1}: ${chapter.title}`,
                    50,
                    null,
                    {
                        continued: true,
                        align: 'left'
                    }
                )
                .text(
                    `  ${currentPage}`,
                    {
                        align: 'right'
                    }
                );

            pageNumbers.push(currentPage);
            currentPage++; 
            doc.moveDown(0.5);
        });

        blog.chapters.forEach((chapter, index) => {
            doc.addPage();

            doc.fontSize(24)
                .font('Helvetica-Bold')
                .text(`Chapter ${index + 1}: ${chapter.title}`, {
                    align: 'center',
                    underline: true
                });

            doc.moveDown(2);

            if (typeof chapter.content === 'string') {
                doc.fontSize(12)
                    .font('Helvetica')
                    .text(chapter.content, {
                        align: 'justify',
                        indent: 20,
                        lineGap: 7
                    });
            } else if (chapter.content && Array.isArray(chapter.content)) {
                chapter.content.forEach(block => {
                    if (typeof block === 'string') {
                        doc.fontSize(12)
                            .font('Helvetica')
                            .text(block, {
                                align: 'justify',
                                indent: 20,
                                lineGap: 7
                            });
                        doc.moveDown();
                    }
                });
            } else if (chapter.content && chapter.content.blocks) {
                chapter.content.blocks.forEach(block => {
                    switch (block.type) {
                        case 'paragraph':
                            doc.fontSize(12)
                                .font('Helvetica')
                                .text(block.data.text, {
                                    align: 'justify',
                                    indent: 20,
                                    lineGap: 7
                                });
                            doc.moveDown();
                            break;
                        case 'header':
                            doc.fontSize(16)
                                .font('Helvetica-Bold')
                                .text(block.data.text, {
                                    align: 'left',
                                    indent: 10
                                });
                            doc.moveDown();
                            break;
                        case 'quote':
                            doc.fontSize(12)
                                .font('Helvetica-Oblique')
                                .text(block.data.text, {
                                    align: 'center',
                                    indent: 30,
                                    lineGap: 7
                                });
                            doc.moveDown();
                            break;
                    }
                });
            }
            doc.fontSize(10)
                .font('Helvetica')
                .text(
                    `Page ${pageNumbers[index]}`,
                    doc.page.width - 100,
                    doc.page.height - 50,
                    { align: 'right' }
                );
        });

        doc.fontSize(10)
            .font('Helvetica-Oblique')
            .text(
                `Downloaded on ${new Date().toLocaleDateString()}`,
                { align: 'center' }
            )
            .moveDown()
            .text(
                'All rights reserved. This document is for personal use only.',
                { align: 'center' }
            );

        doc.end();

    } catch (error) {
        console.error("Error generating PDF:", error);
        if (!res.headersSent) {
            return res.status(500).json({
                error: "Failed to generate PDF",
                details: error.message
            });
        }
    }
});

// Bookmark/unbookmark chapter
server.post("/bookmark-chapter", verifyJWT, async (req, res) => {
    try {
        const { chapter_id } = req.body;
        const user_id = req.user;

        const chapter = await Chapter.findById(chapter_id);
        if (!chapter) {
            return res.status(404).json({ error: "Chapter not found" });
        }

        const bookmarkIndex = chapter.bookmarkedBy.findIndex(
            bookmark => bookmark.user.toString() === user_id
        );

        let isBookmarked;
        if (bookmarkIndex > -1) {
            // Remove bookmark
            chapter.bookmarkedBy.splice(bookmarkIndex, 1);
            isBookmarked = false;
        } else {
            // Add bookmark
            chapter.bookmarkedBy.push({ user: user_id });
            isBookmarked = true;
        }

        await chapter.save();

        return res.status(200).json({
            isBookmarked,
            message: isBookmarked ? "Chapter bookmarked" : "Bookmark removed"
        });
    } catch (error) {
        console.error("Error in bookmark-chapter:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.get("/user-reading-history", verifyJWT, async (req, res) => {
    try {
        const user_id = req.user;

        const bookmarkedChapters = await Chapter.find({
            'bookmarkedBy.user': user_id
        })
        .populate({
            path: 'blog_id',
            select: 'title blog_id banner author',
            model: Blog
        })
        .sort({ 'bookmarkedBy.bookmarkedAt': -1 })
        .limit(5);

        const latestChapters = await Chapter.find()
            .populate({
                path: 'blog_id',
                select: 'title blog_id banner author',
                model: Blog
            })
            .sort({ publishedAt: -1 })
            .limit(5);

        return res.status(200).json({
            bookmarkedChapters,
            latestChapters
        });
    } catch (error) {
        console.error("Error in /user-reading-history:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.get("/latest-chapters", async (req, res) => {
    try {
        console.log("Fetching latest chapters...");

        const latestChapters = await Chapter.find()
            .populate({
                path: 'blog_id',
                select: 'title blog_id banner author',
                model: Blog,
                populate: {
                    path: 'author',
                    select: 'personal_info.username personal_info.fullname',
                    model: User
                }
            })
            .select('title content publishedAt order')
            .sort({ publishedAt: -1 })
            .limit(10);

        console.log("Found latest chapters:", latestChapters.length);
        
        if (!latestChapters || latestChapters.length === 0) {
            return res.status(200).json({ 
                chapters: [],
                message: "No chapters found",
                success: true 
            });
        }

        const transformedChapters = latestChapters.map(chapter => {
            const plainChapter = chapter.toObject();
            const timeAgo = getTimeAgo(plainChapter.publishedAt);
            
            return {
                ...plainChapter,
                blog_id: {
                    ...plainChapter.blog_id,
                    author: plainChapter.blog_id.author
                },
                timeAgo
            };
        });

        return res.status(200).json({ 
            chapters: transformedChapters,
            success: true
        });

    } catch (error) {
        console.error("Error in /latest-chapters:", error);
        return res.status(500).json({ 
            error: "Failed to fetch latest chapters",
            details: error.message
        });
    }
});

const getTimeAgo = (date) => {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    
    let interval = seconds / 31536000; 
    if (interval > 1) {
        return Math.floor(interval) + " years ago";
    }
    
    interval = seconds / 2592000; 
    if (interval > 1) {
        return Math.floor(interval) + " months ago";
    }
    
    interval = seconds / 86400; 
    if (interval > 1) {
        return Math.floor(interval) + " days ago";
    }
    
    interval = seconds / 3600; 
    if (interval > 1) {
        return Math.floor(interval) + " hours ago";
    }
    
    interval = seconds / 60; 
    if (interval > 1) {
        return Math.floor(interval) + " minutes ago";
    }
    
    if(seconds < 10) return "just now";
    
    return Math.floor(seconds) + " seconds ago";
};

server.get("/get-last-chapter-order/:blog_id", verifyJWT, async (req, res) => {
    try {
        const { blog_id } = req.params;
        
        const blog = await Blog.findOne({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        const lastChapter = await Chapter.findOne({ blog_id: blog._id })
            .sort({ order: -1 })
            .select('order');

        const lastOrder = lastChapter ? lastChapter.order : 0;
        
        return res.status(200).json({ lastOrder });
    } catch (error) {
        console.error("Error getting last chapter order:", error);
        return res.status(500).json({ error: error.message });
    }
});

server.get("/admin/dashboard-stats", verifyJWT, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        
        const totalStories = await Blog.countDocuments({ draft: false });
        
        const totalPremiumUsers = await User.countDocuments({ premium: true });
        
        const blogs = await Blog.find({ draft: false });
        const totalViews = blogs.reduce((acc, blog) => acc + (blog.activity?.total_reads || 0), 0);

        const recentUsers = await User.find()
            .select('personal_info.fullname personal_info.email personal_info.profile_img')
            .sort({ createdAt: -1 })
            .limit(5);

        const userGrowth = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        const storyStats = await Blog.aggregate([
            {
                $match: {
                    publishedAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$publishedAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        const categories = await Category.find();
        const categoryDistribution = await Promise.all(
            categories.map(async (category) => {
                const count = await Blog.countDocuments({ 
                    tags: category.name.toLowerCase(),
                    draft: false
                });
                return {
                    name: category.name,
                    count
                };
            })
        );

        res.status(200).json({
            totalUsers,
            totalStories,
            totalPremiumUsers,
            totalViews,
            recentUsers: recentUsers.map(user => ({
                fullname: user.personal_info.fullname,
                email: user.personal_info.email,
                profile_img: user.personal_info.profile_img
            })),
            userGrowth: userGrowth.map(item => ({
                date: item._id,
                count: item.count
            })),
            storyStats: storyStats.map(item => ({
                date: item._id,
                count: item.count
            })),
            categoryDistribution
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
});

server.listen(PORT, () => {
    console.log(`Listening on port -> ${PORT}`);
});
