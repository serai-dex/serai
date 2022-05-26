// For n existing inputs, and n target outputs, multiplex the inputs in while log scheduling the
// outputs out. Monero, which has a limit of 16 TXOs, could do 15 at a time, carrying a change
// Combined with the 20 minute lock, this is completely infeasible. By instead doing 15 TX seeds,
// and then 16 outputs on each, in just two lock cycles you can accomplish 240 TXs (not just 30).
