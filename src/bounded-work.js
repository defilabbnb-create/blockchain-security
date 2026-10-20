// A timed-out OS operation may still be blocked. Keep its slot until it settles:
// callers fail promptly without starting more reads in an exhausted worker pool.
export function boundedSingleFlight(operation, timeoutMs = 5000) {
  let flight = null;
  return (...args) => {
    if (flight) return flight;
    let timer;
    const pending = Promise.resolve().then(() => operation(...args));
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('读取超时，请检查项目文件访问权限'), { status: 503 })), timeoutMs);
    });
    flight = Promise.race([pending, timeout]);
    const release = () => { clearTimeout(timer); flight = null; };
    pending.then(release, release);
    return flight;
  };
}
