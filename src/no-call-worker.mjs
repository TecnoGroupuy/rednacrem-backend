import { processNoCallJob } from "../index.mjs";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-2" });

const QUEUE_URL = process.env.NO_CALL_IMPORT_QUEUE_URL;
const MAX_MILLIS = Number(process.env.NO_CALL_WORKER_MAX_MILLIS || 600000);

async function requeue(jobId, startAt) {
  if (!QUEUE_URL) {
    console.warn("[no-call-worker] NO_CALL_IMPORT_QUEUE_URL not set; cannot requeue");
    return;
  }
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: QUEUE_URL,
      MessageBody: JSON.stringify({ jobId, startAt }),
    })
  );
}

export const handler = async (event) => {
  if (!event?.Records?.length) return;
  for (const record of event.Records) {
    const body = record.body ? JSON.parse(record.body) : {};
    const jobId = body.jobId;
    const startAt = Number.isInteger(body.startAt) ? body.startAt : undefined;
    if (!jobId) continue;
    await processNoCallJob(jobId, {
      startAt,
      maxMillis: MAX_MILLIS,
      requeue: async (nextIndex) => requeue(jobId, nextIndex),
    });
  }
};
