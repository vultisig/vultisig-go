package vault

import (
	session "go-wrapper/go-dkls/sessions"
	eddsaSession "go-wrapper/go-schnorr/sessions"
)

type Handle int32

type MPCKeygenWrapper interface {
	KeygenSetupMsgNew(threshold int, keyID []byte, ids []byte) ([]byte, error)
	KeygenSessionFromSetup(setup []byte, id []byte) (Handle, error)
	KeygenSessionOutputMessage(session Handle) ([]byte, error)
	KeygenSessionInputMessage(session Handle, message []byte) (bool, error)
	KeygenSessionMessageReceiver(session Handle, message []byte, index int) (string, error)
	KeygenSessionFinish(session Handle) (Handle, error)
	KeygenSessionFree(session Handle) error
}

type MPCQcWrapper interface {
	QcSetupMsgNew(keyshareHandle Handle, threshold int, ids []string, oldParties []int, newParties []int) ([]byte, error)
	QcSessionFromSetup(setupMsg []byte, id string, keyshareHandle Handle) (Handle, error)
	QcSessionOutputMessage(session Handle) ([]byte, error)
	QcSessionMessageReceiver(session Handle, message []byte, index int) (string, error)
	QcSessionInputMessage(session Handle, message []byte) (bool, error)
	QcSessionFinish(session Handle) (Handle, error)
}

type MPCKeyshareWrapper interface {
	KeyshareFromBytes(buf []byte) (Handle, error)
	KeyshareToBytes(share Handle) ([]byte, error)
	KeysharePublicKey(share Handle) ([]byte, error)
	KeyshareChainCode(share Handle) ([]byte, error)
	KeyshareFree(share Handle) error
}

var _ MPCKeygenWrapper = &MPCWrapperImp{}
var _ MPCKeyshareWrapper = &MPCWrapperImp{}

type MPCWrapperImp struct {
	isEdDSA bool
}

func NewMPCWrapperImp(isEdDSA bool) *MPCWrapperImp {
	return &MPCWrapperImp{
		isEdDSA: isEdDSA,
	}
}

func (w *MPCWrapperImp) KeygenSetupMsgNew(threshold int, keyID []byte, ids []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSetupMsgNew(int32(threshold), keyID, ids)
	}
	return session.DklsKeygenSetupMsgNew(threshold, keyID, ids)
}

func (w *MPCWrapperImp) KeygenSessionFromSetup(setup []byte, id []byte) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeygenSessionFromSetup(setup, id)
		return Handle(h), err
	}
	h, err := session.DklsKeygenSessionFromSetup(setup, id)
	return Handle(h), err
}

func (w *MPCWrapperImp) KeygenSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionOutputMessage(eddsaSession.Handle(h))
	}
	return session.DklsKeygenSessionOutputMessage(session.Handle(h))
}

func (w *MPCWrapperImp) KeygenSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionInputMessage(eddsaSession.Handle(h), message)
	}
	return session.DklsKeygenSessionInputMessage(session.Handle(h), message)
}

func (w *MPCWrapperImp) KeygenSessionMessageReceiver(h Handle, message []byte, index int) (string, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionMessageReceiver(eddsaSession.Handle(h), message, uint32(index))
	}
	return session.DklsKeygenSessionMessageReceiver(session.Handle(h), message, index)
}

func (w *MPCWrapperImp) KeygenSessionFinish(h Handle) (Handle, error) {
	if w.isEdDSA {
		h1, err := eddsaSession.SchnorrKeygenSessionFinish(eddsaSession.Handle(h))
		return Handle(h1), err
	}
	h1, err := session.DklsKeygenSessionFinish(session.Handle(h))
	return Handle(h1), err
}

func (w *MPCWrapperImp) KeygenSessionFree(h Handle) error {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionFree(eddsaSession.Handle(h))
	}
	return session.DklsKeygenSessionFree(session.Handle(h))
}

func (w *MPCWrapperImp) KeyshareToBytes(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeyshareToBytes(eddsaSession.Handle(share))
	}
	return session.DklsKeyshareToBytes(session.Handle(share))
}

func (w *MPCWrapperImp) KeysharePublicKey(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeysharePublicKey(eddsaSession.Handle(share))
	}
	return session.DklsKeysharePublicKey(session.Handle(share))
}

func (w *MPCWrapperImp) KeyshareChainCode(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return nil, nil // EdDSA doesn't have chain codes
	}
	return session.DklsKeyshareChainCode(session.Handle(share))
}

func (w *MPCWrapperImp) KeyshareFree(share Handle) error {
	if w.isEdDSA {
		return nil // EdDSA handles cleanup automatically
	}
	return session.DklsKeyshareFree(session.Handle(share))
}

func (w *MPCWrapperImp) QcSetupMsgNew(keyshareHandle Handle, threshod int, ids []string, oldParties []int, newParties []int) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSetupMsgNew(eddsaSession.Handle(keyshareHandle), threshod, ids, oldParties, newParties)
	}
	return session.DklsQcSetupMsgNew(session.Handle(keyshareHandle), threshod, ids, oldParties, newParties)
}

func (w *MPCWrapperImp) QcSessionFromSetup(setupMsg []byte, id string, keyshareHandle Handle) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrQcSessionFromSetup(setupMsg, id, eddsaSession.Handle(keyshareHandle))
		return Handle(h), err
	}
	h, err := session.DklsQcSessionFromSetup(setupMsg, id, session.Handle(keyshareHandle))
	return Handle(h), err
}

func (w *MPCWrapperImp) QcSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionOutputMessage(eddsaSession.Handle(h))
	}
	return session.DklsQcSessionOutputMessage(session.Handle(h))
}

func (w *MPCWrapperImp) QcSessionMessageReceiver(h Handle, message []byte, index int) (string, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionMessageReceiver(eddsaSession.Handle(h), message, index)
	}
	return session.DklsQcSessionMessageReceiver(session.Handle(h), message, index)
}

func (w *MPCWrapperImp) QcSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionInputMessage(eddsaSession.Handle(h), message)
	}
	return session.DklsQcSessionInputMessage(session.Handle(h), message)
}

func (w *MPCWrapperImp) QcSessionFinish(h Handle) (Handle, error) {
	if w.isEdDSA {
		h1, err := eddsaSession.SchnorrQcSessionFinish(eddsaSession.Handle(h))
		return Handle(h1), err
	}
	shareHandle, err := session.DklsQcSessionFinish(session.Handle(h))
	return Handle(shareHandle), err
}

func (w *MPCWrapperImp) KeyshareFromBytes(buf []byte) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeyshareFromBytes(buf)
		return Handle(h), err
	}
	h, err := session.DklsKeyshareFromBytes(buf)
	return Handle(h), err
}
