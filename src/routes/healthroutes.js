import { Router } from "express";
import { healthCheck } from "../controllers/health-controllers.js";
const router=Router ();
router.route("/").get(healthCheck)
router.route("/insta").get(healthCheck)
export default router