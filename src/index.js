import dotenv from "dotenv"
import connectDB from "./db/index.db.js"
import { app } from "./app.js";

dotenv.config({
    path: './.env'
})

const port = process.env.PORT || 4000

connectDB()
.then(() => {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);  
    })
})
.catch((error) => {
    console.log(`MONGODB connection failed on server side ${error}`);
    
})

