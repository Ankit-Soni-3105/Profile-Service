rs.initiate({
  _id: "rs0",
  members: [
    { _id: 0, host: "mongo-primary:27017", priority: 1 },
    { _id: 1, host: "mongo-secondary-1:27017", priority: 0.5 },
    { _id: 2, host: "mongo-secondary-2:27017", priority: 0.5 }
  ]
});