package com.prai.opa;

public interface FileBasedAuthz extends Authz {
    public void init(String file1, String file2);
    public void init(String file1, String file2,String file3);
}
