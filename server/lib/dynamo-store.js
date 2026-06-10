'use strict';
/**
 * DynamoDB-backed data store — drop-in replacement for createJsonStore.
 *
 * Each store maps to one DynamoDB table.
 * Items are stored with pk = tenantId, sk = record id.
 * All record fields are stored as a DynamoDB Map via DocumentClient.
 */

const { DynamoDBClient }         = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient,
        PutCommand, GetCommand,
        DeleteCommand, ScanCommand,
        BatchWriteCommand }       = require('@aws-sdk/lib-dynamodb');

const REGION = process.env.AWS_REGION || 'ap-south-1';

const _raw = new DynamoDBClient({ region: REGION });
const ddb  = DynamoDBDocumentClient.from(_raw, {
  marshallOptions:   { removeUndefinedValues: true },
  unmarshallOptions: { wrapNumbers: false },
});

/**
 * Load all items for a tenant from a DynamoDB table.
 * Returns an object keyed by record id (matches existing JSON store shape).
 */
async function loadTable(tableName, tenantId) {
  const result = {};
  let lastKey;
  do {
    const cmd = new ScanCommand({
      TableName:                 tableName,
      FilterExpression:          'pk = :t',
      ExpressionAttributeValues: { ':t': tenantId },
      ExclusiveStartKey:         lastKey,
    });
    const resp = await ddb.send(cmd);
    for (const item of (resp.Items || [])) {
      const { pk, sk, ...data } = item;   // strip DDB keys, return just data
      result[sk] = data;
    }
    lastKey = resp.LastEvaluatedKey;
  } while (lastKey);
  return result;
}

/**
 * Save (upsert) a single record.
 */
async function putItem(tableName, tenantId, id, data) {
  await ddb.send(new PutCommand({
    TableName: tableName,
    Item:      { pk: tenantId, sk: id, ...data },
  }));
}

/**
 * Delete a single record by id.
 */
async function deleteItem(tableName, tenantId, id) {
  await ddb.send(new DeleteCommand({
    TableName: tableName,
    Key:       { pk: tenantId, sk: id },
  }));
}

/**
 * Batch-write an entire records object { id: data, ... } to a table.
 * Used by the migration script.
 */
async function batchPut(tableName, tenantId, records) {
  const ids    = Object.keys(records);
  const chunks = [];
  for (let i = 0; i < ids.length; i += 25) chunks.push(ids.slice(i, i + 25));
  for (const chunk of chunks) {
    await ddb.send(new BatchWriteCommand({
      RequestItems: {
        [tableName]: chunk.map(id => ({
          PutRequest: { Item: { pk: tenantId, sk: id, ...records[id] } },
        })),
      },
    }));
  }
}

/**
 * createDynamoStore — mirrors the existing createJsonStore() API.
 *
 * Usage:
 *   const store = createDynamoStore({ tableName, tenantId, onError });
 *   const data  = await store.load();     // returns { id: record, ... }
 *   await store.put(id, record);          // upsert one record
 *   await store.remove(id);              // delete one record
 *   await store.saveAll(data);           // replace all (used in bulk ops)
 */
function createDynamoStore({ tableName, tenantId, onError }) {
  return {
    async load() {
      try {
        return await loadTable(tableName, tenantId);
      } catch (err) {
        if (onError) onError(err);
        return {};
      }
    },
    async put(id, record) {
      try {
        await putItem(tableName, tenantId, id, record);
      } catch (err) {
        if (onError) onError(err);
      }
    },
    async remove(id) {
      try {
        await deleteItem(tableName, tenantId, id);
      } catch (err) {
        if (onError) onError(err);
      }
    },
    async saveAll(records) {
      try {
        await batchPut(tableName, tenantId, records);
      } catch (err) {
        if (onError) onError(err);
      }
    },
  };
}

module.exports = { createDynamoStore, loadTable, putItem, deleteItem, batchPut };
