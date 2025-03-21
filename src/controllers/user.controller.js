import {asyncHander} from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.utils.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.utils.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";


const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}
        
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHander( async (req, res, next) => {

    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // return res

    const {fullName, username, email, password} = req.body

    if(
        [fullName, username, email, password].some((field) => field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })

    if(existedUser){
        throw new ApiError(401, "User already exists")
    };

    const avatarLocalPath = req.files?.avatar[0]?.path
    
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0 ){
        coverImageLocalPath = req.files.coverImage[0].path
    }


    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar file is missing")
    }

    const user = await User.create({
        fullName,
        avatar: avatar?.url,
        email,
        username: username.toLowerCase(),
        coverImage: coverImage?.url || "",
        password
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    
    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registring user")
    }
    
    res.status(201).json(
        new ApiResponse(200, "User register successfully", createdUser)
    )

})

const loginUser = asyncHander( async (req, res) => {

    // req body -> data
    // username or email
    // find the user
    // password check
    // generate refresh token and access token
    // send cookie

    const {email, username, password} = req.body

    if(!(username || email)){
        throw new ApiError(400, "Username or email is required")
    } 

    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    
    if(!user){
        throw new ApiError(404, "User dos not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)
    
    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logoutUser = asyncHander( async (req, res) => {

    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))

})

const refreshAccessToken = asyncHander(async (req, res) => {
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        
        const user = await User.findById(decodedToken?._id)
        
        if(!user){
            throw new ApiError(401, "Invalid refresh token")
        }
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newrefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res.status(200
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newrefreshToken, options)
            .json(
                new ApiResponse(200, {accessToken, refreshToken: newrefreshToken}, "Access token refreshed" )
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
    
})

const changeCurrentPassword = asyncHander ( async (req, res) => {

    const {oldPassword, newPassword} = req.body
    
    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res.status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))  
})

const getCurrentUser = asyncHander(async (req, res) => {
    return res.status(200)
    .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHander( async (req, res) => {
    const {fullName, email} = req.body

    if(!(fullName || email)){
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
    
})

const updateUserAvatar = asyncHander(async(req, res) => {
    const avatarLocalPath = req.file?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, "Avatar updated"))
})

const updateUserCoverImage = asyncHander( async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "CoverImage file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading on coverImage")
    }
    
    const user = await User.findByIdAndUpdate(
        req.file?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {
            new: true
        }
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, "CoverImage updation successfully"))
    
})

const getUserChannelProfile = asyncHander( async (req, res) => {
    const {username} = req.params

    if(!username?.trim()) {
        throw new ApiError(400, "username is missing")
    }

    const channel =  await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelSSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelSSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1


            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(404, "channel does not exists")
    }
    
    console.log("channel details ",channel);
    
    return res.status(200)
    .json(
        new ApiResponse(200, channel[0],  "User channel fetched successfully")
    )

})

const getWatchHistory = asyncHander( async(req, res) => {

    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owser: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res.status(200)
    .json(
        new ApiResponse(200, user[0].watchHistory, "Watch history fetched successfully")
    )

})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}