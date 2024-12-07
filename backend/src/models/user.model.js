import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true
        },
        
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        }, 
        
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true,
        },
        
        avatar: {
            type: String, // cloudinary url
            required: true,
        },
        
        coverImage: {
            type: String, // cloudinary url
        },
        
        watchHistory:[
            {
                type: Schema.Types.ObjectId,
                ref: 'Video',
            }
        ],
        
        password: {
            type: String,
            required: [true, "Password is Required"],
        },

        refreshToken: {
            type: String,
        },

    },
    {
        timestamps: true

    }
)

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")){
        return next();
    }
    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function (password){
    return await bcrypt.compare(password, this.password)
}


userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)



// Following appeared on installing below: 
// PS C:\Users\ASUS\Documents\Visual Code\Backend\Express\clipspace> npm i bcrypt jsonwebtoken
// Debugger attached.
// npm warn deprecated inflight@1.0.6: This module is not supported, and leaks memory. Do not use it. Check out lru-cache if you want a good and tested way to coalesce async requests by a key value, which is much more comprehensive and powerful.
// npm warn deprecated rimraf@3.0.2: Rimraf versions prior to v4 are no longer supported
// npm warn deprecated glob@7.2.3: Glob versions prior to v9 are no longer supported
// npm warn deprecated npmlog@5.0.1: This package is no longer supported.
// npm warn deprecated are-we-there-yet@2.0.0: This package is no longer supported.
// npm warn deprecated gauge@3.0.2: This package is no longer supported.

// added 61 packages, and audited 185 packages in 18s      

// 23 packages are looking for funding
//   run `npm fund` for details

// found 0 vulnerabilities