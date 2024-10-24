import { Response, Router, Request } from "express";

const router = Router();

router.get("/", async (req: Request, res: Response) => {
  res.status(201).send("amqp index")
})

export default router