using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Steganography
{
    public struct Arguments
    {
        public static Arguments Parse(string[] args, char keySelector = '/')
        {
            Arguments arguments = new Arguments();
            arguments._dictionary = new Dictionary<string, List<string>>();
            arguments.KeylessArguments = new List<string>();
            bool isKeyless = true;
            for(int i = 0; i < args.Length; i++)
            {
                if (args[i].Length > 0 && args[i][0] == keySelector)
                {
                    isKeyless = false;
                    string key = args[i].Replace(keySelector.ToString(), "");
                    List<string> values = new List<string>();
                    while(i < args.Length - 1)
                    {
                        i++;
                        if (args[i][0] == keySelector)
                        {
                            // continue with next key argument
                            i--;
                            break;
                        }
                        else
                        {
                            values.Add(args[i]);
                        }
                    }
                    if (!arguments._dictionary.ContainsKey(key)) arguments._dictionary.Add(key, values);
                }
                else if (isKeyless)
                {
                    arguments.KeylessArguments.Add(args[i]);
                }
            }

            return arguments;
        }

        public List<string> KeylessArguments;
        private Dictionary<string, List<string>> _dictionary;
        
        public string[] this[string key]
        {
            get
            {
                return _dictionary[key].ToArray();
            }
            set
            {
                _dictionary[key] = value.ToList();
            }
        }
        public string this[int key]
        {
            get
            {
                return KeylessArguments[key];
            }
        }

        public int Length => KeylessArguments.Count + _dictionary.Count;
        public bool ContainsKey(string key) => _dictionary.ContainsKey(key);

        public bool ContainsPattern(string key, params Type[] types)
        {
            if (!_dictionary.ContainsKey(key)) return false;
            List<string> keyValues = _dictionary[key];
            if (types.Length > keyValues.Count) return false;
            for (int i = 0; i < keyValues.Count; i++)
            {
                for (int j = 0; j < types.Length; j++)
                {
                    if (types[j] == typeof(string)) continue; // A string is always convertable to a string.

                    object typeVal = null;
                    try
                    {
                        typeVal = Convert.ChangeType(keyValues[i], types[j]);
                    }
                    catch { }
                    if (typeVal == null) return false;
                }
            }
            return true;
        }
    }
}
