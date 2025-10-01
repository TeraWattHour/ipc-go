function init(args)
  local tid = tonumber(tostring(thread):match("%d+")) or 0
  math.randomseed(os.time() + tid)
end

local function randip()
  return string.format("%d.%d.%d.%d", math.random(1, 255), math.random(0, 255), math.random(0, 255), math.random(1, 254))
end

request = function()
  local ip = randip()
  local path = "/resolve/country/" .. ip
  return wrk.format("GET", path)
end
