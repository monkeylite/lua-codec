local codec = require('codec')

for k, v in pairs(codec) do
  print(k, type(v))
end
