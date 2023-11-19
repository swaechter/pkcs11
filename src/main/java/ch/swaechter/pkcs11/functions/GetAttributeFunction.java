package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkAttributeValue;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Obtains an attribute value of an object from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetAttributeFunction extends AbstractFunction {

    /**
     * Create a new function that obtains an attribute value of an object.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetAttributeFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena                     Memory arena
     * @param sessionId                 ID of the session
     * @param objectHandleId            ID of the object handle
     * @param ckAttributeSearchTemplate Search template
     * @return Attribute values
     * @throws Pkcs11Exception Thrown if the session does not exist or the attributes can't be read
     */
    public List<byte[]> invokeFunction(Arena arena, long sessionId, long objectHandleId, List<CkAttributeValue> ckAttributeSearchTemplate) throws Pkcs11Exception {
        try {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_GetAttributeValue", functionDescriptor);

            // Create a struct array with the attributes
            MemorySegment attributesMemorySegment = arena.allocate(MemoryLayout.sequenceLayout(ckAttributeSearchTemplate.size(), getTemplate().getCkAttributeLayout()));

            // Fill in all values
            List<MemorySegment> allocatedMemorySegments = new ArrayList<>(ckAttributeSearchTemplate.size());
            for (int i = 0; i < ckAttributeSearchTemplate.size(); i++) {
                // TODO: Don't use fixed memory allocation
                // Allocate the buffer
                MemorySegment sizeMemorySegment = getTemplate().allocateLongArray(arena, 2000);
                allocatedMemorySegments.add(sizeMemorySegment);

                // Get the attribute
                CkAttributeValue ckAttribute = ckAttributeSearchTemplate.get(i);
                getTemplate().getCkAttributeTypeHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), ckAttribute.type().value);
                getTemplate().getCkAttributePValueHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), sizeMemorySegment);
                getTemplate().getCkAttributeValueLenHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), (int) sizeMemorySegment.byteSize());
            }

            // Invoke the function to get the sizes we have to allocate
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) objectHandleId, attributesMemorySegment, 1));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetAttributeValue failed", ckResult);
            }

            // Convert all values
            List<byte[]> returnValues = new ArrayList<>(ckAttributeSearchTemplate.size());
            for (int i = 0; i < ckAttributeSearchTemplate.size(); i++) {
                byte[] data = getBytes(allocatedMemorySegments.get(i));
                int value = (int) getTemplate().getCkAttributeValueLenHandle().get(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()));
                byte[] realData = Arrays.copyOf(data, value);
                returnValues.add(realData);
            }

            // Return the values
            return returnValues;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetAttributeValue failed: " + throwable.getMessage(), throwable);
        }
    }
}
