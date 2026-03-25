import { processNoCallJob, processDatosTrabajarJob } from "../index.mjs";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-2" });

const QUEUE_URL = process.env.NO_CALL_IMPORT_QUEUE_URL;
const MAX_MILLIS = Number(process.env.NO_CALL_WORKER_MAX_MILLIS || 600000);

async function requeue(jobId, startAt, type = "no_call") {
  if (!QUEUE_URL) {
    console.warn("[no-call-worker] NO_CALL_IMPORT_QUEUE_URL not set; cannot requeue");
    return;
  }
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: QUEUE_URL,
      MessageBody: JSON.stringify({ jobId, startAt, type }),
    })
  );
}

export const handler = async (event) => {
  console.log("WORKER EVENT", JSON.stringify(event, null, 2));
  if (!event?.Records?.length) return;
  for (const record of event.Records) {
    const body = record.body ? JSON.parse(record.body) : {};
    const jobId = body.jobId;
    const startAt = Number.isInteger(body.startAt) ? body.startAt : undefined;
    const type = body.type || "no_call";
    if (!jobId) continue;
    console.log("WORKER JOB", JSON.stringify({ jobId, startAt, type }));
    if (type === "datos_para_trabajar") {
      await processDatosTrabajarJob(jobId, {
        startAt,
        maxMillis: MAX_MILLIS,
        requeue: async (nextIndex) =>
          requeue(jobId, nextIndex, "datos_para_trabajar")
      });
    } else {
      await processNoCallJob(jobId, {
        startAt,
        maxMillis: MAX_MILLIS,
        requeue: async (nextIndex) => requeue(jobId, nextIndex),
      });
    }
  }
};
